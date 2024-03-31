use clap::Parser;
use dashmap::DashMap;
use std::time::Duration;

mod js;
mod links;
use links::{get_links, get_script_sources};
mod http;
mod secrets;

#[derive(Parser, Debug)]
#[command(author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"), about = env!("CARGO_PKG_DESCRIPTION"), long_about = None)]
struct Args {
    /// Include sources of findings
    #[arg(short = 'c', long = "cite")]
    cite: bool,

    /// Include noisy regex patterns
    #[arg(short = 'a', long = "all")]
    all: bool,

    //TODO add output file functionality
    /// Number of concurrent requests, with 10 being the default
    #[arg(short = 't', long = "threads", default_value = "25")]
    threads: usize,

    /// Debug mode
    #[arg(short = 'd', long = "debug", default_value = "false")]
    debug: bool,

    /// Print all URLs instead of secrets or strings
    #[arg(short = 'u', long = "urls", default_value = "false")]
    urls: bool,

    /// Find secrets with regex patterns rather than strings
    #[arg(short = 's', long = "secrets", default_value = "false")]
    secrets: bool,

    /// Use file instead of URL
    #[arg(short = 'f', long = "file")]
    file: Option<String>,

    /// URL to search
    url: Option<String>,
}

struct WorkerOptions {
    debug: bool,
    urls: bool,
    secrets: bool,
    cite: bool,
    noisy: bool,
}

// TODO: Each worker needs to output results to either an mpsc channel with a thread collecting results into findings_map and errors, or directly into findings_map and sending errors to stderr
async fn process_url(
    url: &String,
    options: &WorkerOptions,
    client: &reqwest::Client,
    output: tokio::sync::mpsc::Sender<String>,
) {
    let mut new_urls = Vec::new();

    let res = match http::get(url, client).await {
        Ok(res) => res,
        Err(e) => {
            if options.debug {
                let message = format!("[WARN] Failed to get {}: {}", url, e);
                output
                    .clone()
                    .send(message)
                    .await
                    .expect("Worker failed to send output");
            }
            return;
        }
    };

    if !(res.status.is_success()) {
        if options.debug {
            let message = format!("[WARN] Failed to get {}: {}", url, res.status);
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
        return;
    }

    if options.debug {
        let message = format!("[INFO] Url: {}\n [INFO] Status: {}", url, res.status);
        output
            .clone()
            .send(message)
            .await
            .expect("Worker failed to send output");
    }

    // Get URLs from the page and sources
    for link in get_links(&res, url).iter() {
        if options.urls {
            let message = format!("{}", link);
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
        new_urls.push(link.to_string());
    }
    for source in get_script_sources(&res, url)
        .expect("get_script_sources error")
        .iter()
    {
        new_urls.push(source.to_string());
    }

    // Get either secrets or strings
    if options.secrets {
        for link in secrets::get_header_secrets(&res, options.noisy) {
            let message: String;
            if options.cite {
                message = format!("{} (Location: {})", link, url); //TODO Find a way to remove duplicate findings, despite being found in different tasks
            } else {
                message = format!("{}", link);
            }
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
        for link in secrets::get_secrets(&res, options.noisy) {
            let message: String;
            if options.cite {
                message = format!("{} (Location: {})", link, url); //TODO Find a way to remove duplicate findings, despite being found in different tasks
            } else {
                message = format!("{}", link);
            }
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
    } else {
        if url.ends_with(".js") {
            for string in js::extract_strings(&res.body) {
                let message: String;
                if options.cite {
                    message = format!("{} (Location: {})", string, url); //TODO Find a way to remove duplicate findings, despite being found in different tasks
                } else {
                    message = format!("{}", string);
                }
                output
                    .clone()
                    .send(message)
                    .await
                    .expect("Worker failed to send output");
            }
        }
        for string in js::get_scripts(&res)
            .expect("Failed to get scripts")
            .iter() // Assuming get_scripts returns a Vec or similar collection
            .flat_map(|script| js::extract_strings(script))
        {
            let message: String;
            if options.cite {
                message = format!("{} (Location: {})", string, url); //TODO Find a way to remove duplicate findings, despite being found in different tasks
            } else {
                message = format!("{}", string);
            }
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let url_map: DashMap<String, bool> = DashMap::new(); // Using a concurrent hashmap to avoid duplicates and race conditions
    let (output_sender, output_receiver) = tokio::sync::mpsc::channel(args.threads);
    let finding_map: DashMap<String, String> = DashMap::new();

    // Parse input and add to url_map
    if let Some(file) = args.file {
        std::fs::read_to_string(file)
            .expect("Failed to read file")
            .lines()
            .map(|line| {
                if line.starts_with("http://") || line.starts_with("https://") {
                    line.to_string()
                } else {
                    format!("https://{}", line)
                }
            })
            .for_each(|url| {
                url_map.insert(url, false);
            });
    } else if let Some(url) = args.url {
        if url.starts_with("http://") || url.starts_with("https://") {
            url_map.insert(url, false);
        } else {
            url_map.insert(format!("https://{}", url), false);
        }
    } else {
        // Print help message if no URL or file is provided
        match Args::try_parse_from(["webscan", "-h"]) {
            Ok(_) => return,
            Err(e) => e.exit(),
        };
    };

    // Create a single producer single concumer channel for each thread that the orchestration thread will use to give them tasks
    let mut senders = Vec::with_capacity(args.threads);
    let mut receivers = Vec::with_capacity(args.threads);
    for _ in 0..args.threads {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        senders.push(Some(tx));
        receivers.push(rx);
    }

    // Spawn a thread for each channel (args.threads num of threads), and have them process any URLs sent the the channels until the channels are closed
    for (_, mut receiver) in receivers.into_iter().enumerate() {
        let output_sender_clone = output_sender.clone();
        let options = WorkerOptions {
            debug: args.debug,
            urls: args.urls,
            secrets: args.secrets,
            cite: args.cite,
            noisy: args.all,
        };
        let http_client = reqwest::Client::new();
        tokio::spawn(async move {
            while let Ok(url) = receiver.try_recv() {
                let url_clone = url.clone();
                process_url(
                    &url_clone,
                    &options,
                    &http_client,
                    output_sender_clone.clone(),
                )
                .await;
            }
        });
    }

    // Orchestration thread will send URLs to each thread and close the channels after the URLs map has been empty for a series of sleep periods
    let mut counter = 0;
    let mut index = 0;
    loop {
        if let Some(entry) = url_map.iter().find(|entry| !*entry.value()) {
            let url = entry.key().clone();
            url_map.insert(url.clone(), true);
            if let Some(sender_opt) = senders.get_mut(index % args.threads) {
                if let Some(sender) = sender_opt.take() {
                    let _ = sender.send(url.to_string());
                }
            }
            counter = 0;
            index += 1;
        } else {
            counter += 1;
            let sleep_duration = Duration::from_secs(1 << counter);
            tokio::time::sleep(sleep_duration).await;
        }

        // If the counter reaches 5 sleep periods with no URLs, close the worker threads and exit.
        if counter >= 5 {
            senders.clear();
            break;
        }
    }
}
