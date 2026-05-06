use std::io::Cursor;

use image::ImageFormat;
use js_sys::{Array, Uint8Array};
use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    Blob, BlobPropertyBag, DragEvent, Event, File, HtmlAnchorElement, HtmlInputElement, Url,
};
use wired_core::{Decoder, Encoder, StegoConfig};

#[component]
pub fn App() -> impl IntoView {
    let (cover_bytes, set_cover_bytes) = create_signal::<Option<Vec<u8>>>(None);
    let (cover_name, set_cover_name) = create_signal(String::from("no carrier selected"));
    let (payload, set_payload) = create_signal(String::from("meet at layer seven"));
    let (key, set_key) = create_signal(String::from("change-me"));
    let (status, set_status) = create_signal(String::from("awaiting carrier image"));
    let (decoded, set_decoded) = create_signal(String::new());
    let (download_url, set_download_url) = create_signal::<Option<String>>(None);

    let load_file = move |file: File| {
        let name = file.name();
        set_status.set(format!("reading carrier: {name}"));
        spawn_local(async move {
            match read_file(file).await {
                Ok(bytes) => {
                    set_cover_bytes.set(Some(bytes));
                    set_cover_name.set(name);
                    set_status.set(String::from("carrier loaded"));
                }
                Err(err) => set_status.set(format!("file read failed: {err:?}")),
            }
        });
    };

    let on_file_change = move |ev: Event| {
        let input = event_target::<HtmlInputElement>(&ev);
        if let Some(files) = input.files() {
            if let Some(file) = files.get(0) {
                load_file(file);
            }
        }
    };

    let on_drop = move |ev: DragEvent| {
        ev.prevent_default();
        if let Some(files) = ev.data_transfer().and_then(|transfer| transfer.files()) {
            if let Some(file) = files.get(0) {
                load_file(file);
            }
        }
    };

    let encode = move |_| {
        let Some(bytes) = cover_bytes.get_untracked() else {
            set_status.set(String::from("load a PNG carrier first"));
            return;
        };
        let payload = payload.get_untracked();
        let key = key.get_untracked();

        set_status.set(String::from("encoding encrypted payload"));
        match encode_png(&bytes, payload.as_bytes(), key.as_bytes()) {
            Ok(png) => match png_download_url(&png) {
                Ok(url) => {
                    set_download_url.set(Some(url));
                    set_status.set(format!("encoded {} bytes into carrier", payload.len()));
                }
                Err(err) => set_status.set(format!("download URL failed: {err:?}")),
            },
            Err(err) => set_status.set(format!("encode failed: {err}")),
        }
    };

    let decode = move |_| {
        let Some(bytes) = cover_bytes.get_untracked() else {
            set_status.set(String::from("load a wired PNG first"));
            return;
        };
        let key = key.get_untracked();

        set_status.set(String::from("extracting payload"));
        match decode_png(&bytes, key.as_bytes()) {
            Ok(data) => {
                set_decoded.set(String::from_utf8_lossy(&data).to_string());
                set_status.set(format!("decoded {} bytes", data.len()));
            }
            Err(err) => set_status.set(format!("decode failed: {err}")),
        }
    };

    view! {
        <main class="shell">
            <section class="hero">
                <p class="eyebrow">"L7 steganography transport"</p>
                <h1>"wired-transport"</h1>
                <p class="lede">
                    "Encrypt, Reed-Solomon shard, and scatter payload bits into PNG RGB LSB channels with deterministic xoshiro mapping."
                </p>
            </section>

            <section class="terminal-grid">
                <div class="panel carrier">
                    <div class="panel-title">"carrier/input"</div>
                    <label
                        class="drop-zone"
                        on:dragover=move |ev| ev.prevent_default()
                        on:drop=on_drop
                    >
                        <input type="file" accept="image/png" on:change=on_file_change />
                        <span class="drop-mark">"DROP PNG"</span>
                        <span class="file-name">{cover_name}</span>
                    </label>
                </div>

                <div class="panel controls">
                    <div class="panel-title">"cipher/session"</div>
                    <label class="field">
                        <span>"shared key"</span>
                        <input
                            type="password"
                            prop:value=key
                            on:input=move |ev| set_key.set(event_target_value(&ev))
                        />
                    </label>
                    <label class="field">
                        <span>"payload"</span>
                        <textarea
                            prop:value=payload
                            on:input=move |ev| set_payload.set(event_target_value(&ev))
                        ></textarea>
                    </label>
                    <div class="buttons">
                        <button on:click=encode>"inject"</button>
                        <button class="secondary" on:click=decode>"extract"</button>
                    </div>
                    <Show when=move || download_url.get().is_some()>
                        <a class="download" href=move || download_url.get().unwrap_or_default() download="wired-carrier.png">
                            "download wired-carrier.png"
                        </a>
                    </Show>
                </div>

                <div class="panel output">
                    <div class="panel-title">"terminal/output"</div>
                    <pre class="status">{move || format!("> {status}", status = status.get())}</pre>
                    <pre class="decoded">{move || decoded.get()}</pre>
                </div>
            </section>
        </main>
    }
}

async fn read_file(file: File) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
    let buffer = JsFuture::from(file.array_buffer()).await?;
    let array = Uint8Array::new(&buffer);
    let mut bytes = vec![0u8; array.length() as usize];
    array.copy_to(&mut bytes);
    Ok(bytes)
}

fn encode_png(input: &[u8], payload: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let image = image::load_from_memory(input).map_err(|err| err.to_string())?;
    let encoded = Encoder::inject_with_config(
        image,
        payload,
        key,
        StegoConfig {
            recovery_rate: 0.25,
            bit_repetition: 15,
        },
    )
    .map_err(|err| err.to_string())?;

    let mut out = Cursor::new(Vec::new());
    encoded
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|err| err.to_string())?;
    Ok(out.into_inner())
}

fn decode_png(input: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let image = image::load_from_memory(input).map_err(|err| err.to_string())?;
    Decoder::extract(image, key).map_err(|err| err.to_string())
}

fn png_download_url(bytes: &[u8]) -> Result<String, wasm_bindgen::JsValue> {
    let array = Uint8Array::from(bytes);
    let parts = Array::new();
    parts.push(&array.buffer());

    let options = BlobPropertyBag::new();
    options.set_type("image/png");
    let blob = Blob::new_with_u8_array_sequence_and_options(&parts, &options)?;
    Url::create_object_url_with_blob(&blob)
}

#[allow(dead_code)]
fn click_download(url: &str) -> Result<(), wasm_bindgen::JsValue> {
    let window = web_sys::window().expect("window");
    let document = window.document().expect("document");
    let anchor = document
        .create_element("a")?
        .dyn_into::<HtmlAnchorElement>()?;
    anchor.set_href(url);
    anchor.set_download("wired-carrier.png");
    anchor.click();
    Ok(())
}
