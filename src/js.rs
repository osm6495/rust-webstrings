use crate::http::HttpResponse;
use regex::Regex;
use scraper::{error::SelectorErrorKind, Html, Selector};

pub fn get_scripts(res: &HttpResponse) -> Result<Vec<String>, SelectorErrorKind> {
    let body = Html::parse_document(&res.body);
    let mut scripts = Vec::new();
    let selector = Selector::parse("script").expect("Failed to parse script selector");
    for element in body.select(&selector) {
        if let Some(script) = element.value().attr("content") {
            scripts.push(script.to_string());
        }
    }

    Ok(scripts)
}

pub fn extract_strings(js: &str) -> Vec<String> {
    let re = Regex::new(r#""([^"\\]*(\\.[^"\\]*)*)"|'([^'\\]*(\\.[^'\\]*)*)'"#).unwrap();

    //Regex patterns for recognizing unwanted minified JS
    let function_pattern = Regex::new(r"function\(").unwrap();
    let var_pattern = Regex::new(r"\bvar\b").unwrap();

    re.captures_iter(js)
        .filter_map(|cap| {
            let cap_str = cap.get(0).map_or(String::new(), |m| m.as_str().to_string());
            if !cap_str.is_empty() //Filter out empty strings
                && cap_str != "\"\"" 
                && cap_str != "''" 
                && !function_pattern.is_match(&cap_str) //Filter out minified JS
                && !var_pattern.is_match(&cap_str)
            {
                Some(cap_str)
            } else {
                None
            }
        })
        .collect()
}
