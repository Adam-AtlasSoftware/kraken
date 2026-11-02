//! Pictures attached to a chat message: pasted, dropped or picked, made a size the model takes.

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use image::{DynamicImage, ImageFormat, RgbaImage};
use kraken_viewmodel::assist::{Attachment, Preview};

/// The longest side the models read in full.
const MAX_SIDE: u32 = 1568;
/// The biggest file a picture may become; providers refuse larger ones.
const MAX_BYTES: usize = 3_700_000;
/// The biggest file read.
const MAX_FILE: u64 = 64 << 20;
const PREVIEW_SIDE: u32 = 120;
/// Pictures on one message.
pub const MAX_ATTACHED: usize = 6;

/// True for a file name that looks like a picture.
pub fn is_image(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        matches!(
            e.to_ascii_lowercase().as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp"
        )
    })
}

/// Reads the picture at `path`.
pub fn from_file(path: &Path) -> Result<Attachment, String> {
    let name = path.display();
    let size = std::fs::metadata(path)
        .map_err(|e| format!("{name} cannot be read: {e}"))?
        .len();
    if size > MAX_FILE {
        return Err(format!("{name} is too big to attach."));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{name} cannot be read: {e}"))?;
    from_bytes(&bytes).map_err(|e| format!("{name}: {e}"))
}

/// Reads a picture from the bytes of its file.
pub fn from_bytes(bytes: &[u8]) -> Result<Attachment, String> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| format!("not a picture KRAKEN can read: {e}"))?;
    finish(img)
}

/// Takes a picture from the clipboard; `None` when it holds no picture.
pub fn from_clipboard() -> Option<Result<Attachment, String>> {
    let shot = arboard::Clipboard::new().ok()?.get_image().ok()?;
    let img = RgbaImage::from_raw(
        u32::try_from(shot.width).ok()?,
        u32::try_from(shot.height).ok()?,
        shot.bytes.into_owned(),
    )?;
    Some(finish(DynamicImage::ImageRgba8(img)))
}

fn encode(img: &DynamicImage, format: ImageFormat) -> Result<Vec<u8>, String> {
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, format)
        .map_err(|e| format!("the picture cannot be prepared: {e}"))?;
    Ok(out.into_inner())
}

fn finish(img: DynamicImage) -> Result<Attachment, String> {
    let img = if img.width().max(img.height()) > MAX_SIDE {
        img.thumbnail(MAX_SIDE, MAX_SIDE)
    } else {
        img
    };
    // Screenshots are smallest and sharpest as PNG; a photo falls back to JPEG.
    let (mut file, mut media_type) = (encode(&img, ImageFormat::Png)?, "image/png");
    if file.len() > MAX_BYTES {
        file = encode(&DynamicImage::ImageRgb8(img.to_rgb8()), ImageFormat::Jpeg)?;
        media_type = "image/jpeg";
    }
    if file.len() > MAX_BYTES {
        return Err("the picture is too big to attach, even made smaller.".to_string());
    }
    let small = img.thumbnail(PREVIEW_SIDE, PREVIEW_SIDE).to_rgba8();
    Ok(Attachment {
        media_type: media_type.to_string(),
        data: base64::engine::general_purpose::STANDARD
            .encode(file)
            .into(),
        preview: Arc::new(Preview {
            width: small.width() as usize,
            height: small.height() as usize,
            rgba: small.into_raw(),
        }),
    })
}

/// Draws a picture at `height`; `attachment` names its texture.
pub fn thumbnail(ui: &mut egui::Ui, a: &Attachment, height: f32) -> egui::Response {
    let id = egui::Id::new(("kraken_attachment", Arc::as_ptr(&a.preview) as usize));
    let texture: egui::TextureHandle = ui.data_mut(|d| d.get_temp(id)).unwrap_or_else(|| {
        let image = egui::ColorImage::from_rgba_unmultiplied(
            [a.preview.width, a.preview.height],
            &a.preview.rgba,
        );
        let t = ui
            .ctx()
            .load_texture("attachment", image, egui::TextureOptions::LINEAR);
        ui.data_mut(|d| d.insert_temp(id, t.clone()));
        t
    });
    let ratio = a.preview.width as f32 / a.preview.height.max(1) as f32;
    ui.add(egui::Image::new(&texture).fit_to_exact_size(egui::vec2(height * ratio, height)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img =
            DynamicImage::ImageRgba8(RgbaImage::from_pixel(w, h, image::Rgba([9, 8, 7, 255])));
        encode(&img, ImageFormat::Png).unwrap()
    }

    #[test]
    fn a_picture_becomes_an_attachment_with_a_small_preview() {
        let a = from_bytes(&png(300, 200)).unwrap();
        assert_eq!(a.media_type, "image/png");
        assert!(a.preview.width <= 120 && a.preview.height <= 120);
        assert_eq!(a.preview.rgba.len(), a.preview.width * a.preview.height * 4);
        let file = base64::engine::general_purpose::STANDARD
            .decode(a.data.as_bytes())
            .unwrap();
        assert_eq!(image::load_from_memory(&file).unwrap().width(), 300);
    }

    #[test]
    fn a_huge_picture_is_made_smaller() {
        let a = from_bytes(&png(4000, 2000)).unwrap();
        let file = base64::engine::general_purpose::STANDARD
            .decode(a.data.as_bytes())
            .unwrap();
        assert_eq!(image::load_from_memory(&file).unwrap().width(), MAX_SIDE);
    }

    #[test]
    fn what_is_not_a_picture_is_refused_in_words() {
        assert!(
            from_bytes(b"not an image")
                .unwrap_err()
                .contains("not a picture")
        );
        assert!(is_image(Path::new("a/b.PNG")) && is_image(Path::new("x.jpeg")));
        assert!(!is_image(Path::new("a.out")) && !is_image(Path::new("noext")));
    }
}
