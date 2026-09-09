use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = window, js_name = fetch)]
    fn fetch_js(url: &str, options: &JsValue);
}

#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    let stripe_key = "sk_live_abcdefghijklmnopqrstuvwx";
    let discord_token = "MTIzNDU2Nzg5MDEyMzQ1Njc4.Gq-123.abcdefghijklmnopqrstuvwxyz12345";
    let jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
    
    let absolute_url = "https://securitymgmt.staging.unifiedapis.example.com";
    let postgres_uri = "postgresql://dbuser:secretpass@database.internal.corp:5432/webapp";

    perform_native_fetch(absolute_url, jwt_token, stripe_key);
    build_db_request(discord_token, postgres_uri);

    Ok(())
}

#[wasm_bindgen]
pub fn perform_native_fetch(url: &str, jwt: &str, stripe: &str) {
    let auth_header = format!("Bearer {} | Stripe: {}", jwt, stripe);
    
    fetch_js(url, &JsValue::from_str(&auth_header));
}

#[wasm_bindgen]
pub fn build_db_request(discord: &str, db_uri: &str) {
    let log_msg = format!("Discord: {} | DB: {}", discord, db_uri);
    web_sys::console::log_1(&JsValue::from_str(&log_msg));
}