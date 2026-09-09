#include <stdio.h>
#include <emscripten.h>

EM_JS(void, perform_native_fetch, (const char* url, const char* jwt, const char* stripe), {
    var url_str = UTF8ToString(url);
    var jwt_str = UTF8ToString(jwt);
    var stripe_str = UTF8ToString(stripe);
    
    console.log("Initiating fetch to: " + url_str + " with token length: " + jwt_str.length);
});

EM_JS(void, build_db_request, (const char* discord, const char* db_uri), {
    var discord_str = UTF8ToString(discord);
    var db_str = UTF8ToString(db_uri);
    console.log("DB configured securely.");
});

int main() {
    printf("Emscripten C/C++ Wasm Lab Initialized...\n");

    const char* stripe_key = "sk_live_abcdefghijklmnopqrstuvwx";
    const char* discord_token = "MTIzNDU2Nzg5MDEyMzQ1Njc4.Gq-123.abcdefghijklmnopqrstuvwxyz12345";
    const char* jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
    
    const char* absolute_url = "https://securitymgmt.staging.unifiedapis.example.com";
    const char* postgres_uri = "postgresql://dbuser:secretpass@database.internal.corp:5432/webapp";

    perform_native_fetch(absolute_url, jwt_token, stripe_key);
    build_db_request(discord_token, postgres_uri);

    return 0;
}