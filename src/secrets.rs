use crate::http::HttpResponse;
use lazy_static::lazy_static;
use regex::Regex;
use reqwest::header::HeaderMap;
use std::collections::HashMap;

lazy_static! {
    pub static ref NOISY_SECRET_REGEX: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Google API Key", "AIza[0-9A-Za-z-_]{35}");
        m.insert("Google OAuth 2.0 Access Token", "ya29.[0-9A-Za-z-_]+");
        m.insert(
            "GitHub Personal Access Token (Classic)",
            "ghp_[a-zA-Z0-9]{36}",
        );
        m.insert(
            "GitHub Personal Access Token (Fine-Grained",
            "github_pat_[a-zA-Z0-9]{22}[a-zA-Z0-9]{59}",
        );
        m.insert("GitHub OAuth 2.0 Access Token", "gho[a-zA-Z0-9]{36}");
        m.insert("GitHub User-to-Server Access Token", "ghu_[a-zA-Z0-9]{36}");
        m.insert(
            "GitHub Server-to-Server Access Token",
            "ghs_[a-zA-Z0-9]{36}",
        );
        m.insert("GitHub Refresh Token", "ghr_[a-zA-Z0-9]{36}");
        m.insert("Foursquare Secret Key", "R_[0-9a-f]{32}");
        m.insert("Picatic API Key", "sk_live_[0-9a-z]{32}");
        m.insert("Stripe Standard API Key", "sk_live_[0-9a-zA-Z]{24}");
        m.insert("Stripe Restricted API Key", "sk_live_[0-9a-zA-Z]{24}");
        m.insert("Square Access Token", "sqOatp-[0-9A-Za-z-]{22}");
        m.insert("Square OAuth Secret", "q0csp-[ 0-9A-Za-z-]{43}");
        m.insert(
            "Paypal / Braintree Access Token",
            "access_token,production$[0-9a-z]{16}[0-9a,]{32}",
        );
        m.insert(
            "Amazon Marketing Services Auth Token",
            "amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}",
        );
        m.insert("Mailgun API Key", "key-[0-9a-zA-Z]{32}");
        m.insert("MailChimp", "[0-9a-f]{32}-us[0-9]{1,2}");
        m.insert(
            "Slack OAuth v2 Bot Access Token",
            "xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        );
        m.insert(
            "Slack OAuth v2 User Access Token",
            "xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        );
        m.insert(
            "Slack OAuth v2 Configuration Token",
            "xoxe.xoxp-1-[0-9a-zA-Z]{166}",
        );
        m.insert("Slack OAuth v2 Refresh Token", "xoxe-1-[0-9a-zA-Z]{147}");
        m.insert(
            "Slack Webhook",
            "T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        );
        m.insert("AWS Access Key ID", "AKIA[0-9A-Z]{16}");
        m.insert(
            "Google Cloud Platform OAuth 2.0",
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        );
        m.insert(
            "Heroku OAuth 2.0",
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        );
        m.insert("Facebook Access Token", "EAACEdEose0cBA[0-9A-Za-z]+");
        m.insert(
            "Facebook OAuth",
            "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].['|\"][0-9a-f]{32}['|\"]",
        );
        m.insert("Twitter Username", r"/(^|[^@\w])@(\w{1,15})\b/");
        m.insert("Twitter Access Token", "[1-9][0-9]+-[0-9a-zA-Z]{40}");
        m.insert("Cloudinary URL", "cloudinary://.");
        m.insert("Firebase URL", r".firebaseio\.com");
        m.insert("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----");
        m.insert("DSA Private Key", "-----BEGIN DSA PRIVATE KEY-----");
        m.insert("EC Private Key", "-----BEGIN EC PRIVATE KEY-----");
        m.insert("PGP Private Key", "-----BEGIN PGP PRIVATE KEY BLOCK-----");
        m.insert(
            "Generic API Key",
            "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].['|\"][0-9a-zA-Z]{32,45}['|\"]",
        );
        m.insert(
            "Password in URL",
            "[a-zA-Z]{3,10}:\\/[^\\s:@]{3,20}:[^\\s:@]{3,20}@.{1,100}[\"'\\s]",
        );
        m.insert(
            "Slack Webhook URL",
            "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        );
        m
    };
}

lazy_static! {
    pub static ref SECRET_REGEX: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Google OAuth 2.0 Access Token", "ya29.[0-9A-Za-z-_]+");
        m.insert(
            "GitHub Personal Access Token (Classic)",
            "ghp_[a-zA-Z0-9]{36}",
        );
        m.insert(
            "GitHub Personal Access Token (Fine-Grained",
            "github_pat_[a-zA-Z0-9]{22}[a-zA-Z0-9]{59}",
        );
        m.insert("GitHub OAuth 2.0 Access Token", "gho[a-zA-Z0-9]{36}");
        m.insert("GitHub User-to-Server Access Token", "ghu_[a-zA-Z0-9]{36}");
        m.insert(
            "GitHub Server-to-Server Access Token",
            "ghs_[a-zA-Z0-9]{36}",
        );
        m.insert("GitHub Refresh Token", "ghr_[a-zA-Z0-9]{36}");
        m.insert("Foursquare Secret Key", "R_[0-9a-f]{32}");
        m.insert("Picatic API Key", "sk_live_[0-9a-z]{32}");
        m.insert("Stripe Standard API Key", "sk_live_[0-9a-zA-Z]{24}");
        m.insert("Stripe Restricted API Key", "sk_live_[0-9a-zA-Z]{24}");
        m.insert("Square Access Token", "sqOatp-[0-9A-Za-z-]{22}");
        m.insert("Square OAuth Secret", "q0csp-[ 0-9A-Za-z-]{43}");
        m.insert(
            "Paypal / Braintree Access Token",
            "access_token,production$[0-9a-z]{16}[0-9a,]{32}",
        );
        m.insert(
            "Amazon Marketing Services Auth Token",
            "amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}",
        );
        m.insert("Mailgun API Key", "key-[0-9a-zA-Z]{32}");
        m.insert("MailChimp", "[0-9a-f]{32}-us[0-9]{1,2}");
        m.insert(
            "Slack OAuth v2 Bot Access Token",
            "xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        );
        m.insert(
            "Slack OAuth v2 User Access Token",
            "xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        );
        m.insert(
            "Slack OAuth v2 Configuration Token",
            "xoxe.xoxp-1-[0-9a-zA-Z]{166}",
        );
        m.insert("Slack OAuth v2 Refresh Token", "xoxe-1-[0-9a-zA-Z]{147}");
        m.insert(
            "Slack Webhook",
            "T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        );
        m.insert("AWS Access Key ID", "AKIA[0-9A-Z]{16}");
        m.insert(
            "Google Cloud Platform OAuth 2.0",
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        );
        m.insert(
            "Heroku OAuth 2.0",
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        );
        m.insert("Facebook Access Token", "EAACEdEose0cBA[0-9A-Za-z]+");
        m.insert(
            "Facebook OAuth",
            "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].['|\"][0-9a-f]{32}['|\"]",
        );
        m.insert("Twitter Username", r"/(^|[^@\w])@(\w{1,15})\b/");
        m.insert("Cloudinary URL", "cloudinary://.");
        m.insert("Firebase URL", r".firebaseio\.com");
        m.insert("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----");
        m.insert("DSA Private Key", "-----BEGIN DSA PRIVATE KEY-----");
        m.insert("EC Private Key", "-----BEGIN EC PRIVATE KEY-----");
        m.insert("PGP Private Key", "-----BEGIN PGP PRIVATE KEY BLOCK-----");
        m.insert(
            "Generic API Key",
            "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].['|\"][0-9a-zA-Z]{32,45}['|\"]",
        );
        m.insert(
            "Password in URL",
            "[a-zA-Z]{3,10}:\\/[^\\s:@]{3,20}:[^\\s:@]{3,20}@.{1,100}[\"'\\s]",
        );
        m.insert(
            "Slack Webhook URL",
            "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        );
        m
    };
}

pub fn get_secrets(res: &HttpResponse, noisy: bool) -> Vec<String> {
    let mut secrets = Vec::new();
    let secrets_regex = if noisy {
        NOISY_SECRET_REGEX.iter()
    } else {
        SECRET_REGEX.iter()
    };

    for (name, regex) in secrets_regex {
        let re = Regex::new(regex).unwrap();

        //Regex patterns for recognizing unwanted minified JS
        let function_pattern = Regex::new(r"function\(").unwrap();
        let var_pattern = Regex::new(r"\bvar\b").unwrap();
        let return_pattern = Regex::new(r"\breturn\b").unwrap();

        //Used to check generic API findings for Google API keys, which require the noisy flag
        let google_pattern = Regex::new(r"AIza[0-9A-Za-z-_]{35}").unwrap();

        for cap in re.captures_iter(res.body.as_str()) {
            if let Some(match_) = cap.get(0) {
                //Remove Google API keys from generic API key findings when noisy flag is not set
                if !noisy && google_pattern.is_match(&cap[0]) {
                    continue;
                }

                //Remove obvious false positives
                if !noisy
                    && (match_.as_str().contains("example")
                        || match_.as_str().contains("test")
                        || match_.as_str().contains("demo"))
                {
                    continue;
                }

                //Remove unwanted minified JS
                if !function_pattern.is_match(&cap[0])
                    && !var_pattern.is_match(&cap[0])
                    && !return_pattern.is_match(&cap[0])
                {
                    secrets.push(format!("{}: {}", name, match_.as_str()));
                }
            }
        }
    }
    secrets
}

pub fn headers_to_string(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{}: {}", name.as_str(), value.to_str().unwrap_or("")))
        .collect::<Vec<String>>()
        .join("\n")
}

pub fn get_header_secrets(res: &HttpResponse, noisy: bool) -> Vec<String> {
    let mut secrets = Vec::new();
    let secrets_regex = if noisy {
        NOISY_SECRET_REGEX.iter()
    } else {
        SECRET_REGEX.iter()
    };

    for (name, regex) in secrets_regex {
        let re = Regex::new(regex).unwrap();

        //Regex patterns for recognizing unwanted minified JS
        let function_pattern = Regex::new(r"function\(").unwrap();
        let var_pattern = Regex::new(r"\bvar\b").unwrap();
        let return_pattern = Regex::new(r"\breturn\b").unwrap();

        //Used to check generic API findings for Google API keys, which require the noisy flag
        let google_pattern = Regex::new(r"AIza[0-9A-Za-z-_]{35}").unwrap();

        for cap in re.captures_iter(headers_to_string(&res.headers).as_str()) {
            if let Some(match_) = cap.get(1) {
                //Remove Google API keys from generic API key findings when noisy flag is not set
                if !noisy && google_pattern.is_match(&cap[0]) {
                    continue;
                }

                if !function_pattern.is_match(&cap[0])
                    && !var_pattern.is_match(&cap[0])
                    && !return_pattern.is_match(&cap[0])
                {
                    secrets.push(format!("{}: {}", name, match_.as_str()));
                }
            }
        }
    }
    secrets
}
