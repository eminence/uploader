use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::ReadableStreamDefaultReader;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}


#[wasm_bindgen]
pub async fn infer(stream: web_sys::ReadableStream) -> Result<JsValue, JsValue> {
    let reader = stream.get_reader();
    
    let reader: ReadableStreamDefaultReader = reader.dyn_into()?;

    let p = JsFuture::from(reader.read()).await?;
    // This will be an object, and we want the "value" field
    let chunk = Reflect::get(&p, &"value".into())?;
    
    let arr: Uint8Array = chunk.dyn_into()?;

    // we have our chunk, so cancel the reader
    JsFuture::from(reader.cancel()).await?;

    if let Some(infer_type) = infer::get(&arr.to_vec()) {
        Ok(infer_type.mime_type().to_string().into())
    } else {
        Ok(JsValue::NULL)
    }
}
