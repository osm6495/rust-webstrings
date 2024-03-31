use reqwest::header::{HeaderMap, USER_AGENT};
use reqwest::StatusCode;
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

pub async fn get(url: &String, client: &reqwest::Client) -> Result<HttpResponse, reqwest::Error> {
    let res = client
        .clone()
        .get(url)
        .header(
            USER_AGENT,
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        )
        .send()
        .await?;
    let res = HttpResponse {
        status: res.status(),
        headers: res.headers().clone(),
        body: res.text().await?,
    };
    Ok(res)
}
