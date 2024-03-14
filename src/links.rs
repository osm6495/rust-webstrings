use crate::http::HttpResponse;
use regex::Regex;
use scraper::{error::SelectorErrorKind, Html, Selector};

pub fn get_links(res: &HttpResponse, base_url: &String) -> Vec<String> {
    //Regex search for links
    let re = Regex::new(
        r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)",
    ).unwrap();
    let mut links = Vec::new();
    for cap in re.captures_iter(res.body.as_str()) {
        if let Some(match_) = cap.get(0) {
            links.push(
                match_
                    .as_str()
                    .to_string()
                    .trim_end_matches("&#34")
                    .to_owned(),
            );
        }
    }

    //Grab links from DOM
    let body = Html::parse_document(&res.body);
    let selector = Selector::parse("a").unwrap();
    for element in body.select(&selector) {
        if let Some(link) = element.value().attr("href") {
            let link = link.trim_end_matches("&#34").to_owned();
            links.push(link);
        }
    }

    for link in links.iter_mut() {
        if link.starts_with('/') || link.starts_with('.') {
            *link = format!("{}{}", base_url, link);
        }
    }

    links
}

pub fn get_script_sources<'a>(
    res: &'a HttpResponse,
    base_url: &str,
) -> Result<Vec<String>, SelectorErrorKind<'a>> {
    let body = Html::parse_document(&res.body);
    let mut sources = Vec::new();
    let selector = Selector::parse("script").expect("failed to parse script selector");
    for element in body.select(&selector) {
        if let Some(script) = element.value().attr("src") {
            sources.push(script.to_string());
        }
    }

    for link in sources.iter_mut() {
        if link.starts_with('/') || link.starts_with('.') {
            *link = format!("{}{}", base_url, link);
        }
    }

    Ok(sources)
}
