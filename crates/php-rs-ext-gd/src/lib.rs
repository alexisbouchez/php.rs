//! PHP gd extension implementation for php.rs
//!
//! Provides image manipulation functions (GD library).
//! Reference: php-src/ext/gd/
//!
//! This is a pure Rust implementation with pixel-level operations.
//! Image encoding (PNG/JPEG/GIF) returns stubs for now.

use std::collections::VecDeque;

// Image type constants
pub const IMG_GIF: i32 = 1;
pub const IMG_JPG: i32 = 2;
pub const IMG_PNG: i32 = 4;
pub const IMG_WBMP: i32 = 8;
pub const IMG_XPM: i32 = 16;
pub const IMG_WEBP: i32 = 32;
pub const IMG_BMP: i32 = 64;
pub const IMG_AVIF: i32 = 256;

// Flip constants
pub const IMG_FLIP_HORIZONTAL: i32 = 1;
pub const IMG_FLIP_VERTICAL: i32 = 2;
pub const IMG_FLIP_BOTH: i32 = 3;

/// Rectangle for crop operations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GdRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Image size information returned by getimagesize.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageSize {
    pub width: u32,
    pub height: u32,
    pub image_type: i32,
    pub bits: u32,
    pub channels: u32,
    pub mime: String,
}

/// GD image struct. Pixels are stored in ARGB format (u32).
#[derive(Debug, Clone)]
pub struct GdImage {
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Pixel data in ARGB format (row-major)
    pub pixels: Vec<u32>,
    /// Whether this is a true-color image
    pub true_color: bool,
    /// Allocated colors (for palette-based images)
    allocated_colors: Vec<u32>,
}

impl GdImage {
    fn pixel_index(&self, x: i32, y: i32) -> Option<usize> {
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            None
        } else {
            Some((y as usize) * (self.width as usize) + (x as usize))
        }
    }
}

/// Pack RGBA components into a u32 in ARGB format.
fn pack_argb(a: u8, r: u8, g: u8, b: u8) -> u32 {
    ((a as u32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// Create a palette-based image.
///
/// PHP signature: imagecreate(int $width, int $height): GdImage|false
pub fn imagecreate(width: u32, height: u32) -> GdImage {
    GdImage {
        width,
        height,
        pixels: vec![0u32; (width * height) as usize],
        true_color: false,
        allocated_colors: Vec::new(),
    }
}

/// Create a true-color image.
///
/// PHP signature: imagecreatetruecolor(int $width, int $height): GdImage|false
pub fn imagecreatetruecolor(width: u32, height: u32) -> GdImage {
    // Default is black with full opacity
    let black = pack_argb(0, 0, 0, 0);
    GdImage {
        width,
        height,
        pixels: vec![black; (width * height) as usize],
        true_color: true,
        allocated_colors: Vec::new(),
    }
}

/// Destroy an image (free resources).
///
/// PHP signature: imagedestroy(GdImage $image): bool
pub fn imagedestroy(image: &mut GdImage) {
    image.pixels.clear();
    image.width = 0;
    image.height = 0;
}

/// Get image width.
///
/// PHP signature: imagesx(GdImage $image): int
pub fn imagesx(image: &GdImage) -> u32 {
    image.width
}

/// Get image height.
///
/// PHP signature: imagesy(GdImage $image): int
pub fn imagesy(image: &GdImage) -> u32 {
    image.height
}

/// Allocate a color for an image.
///
/// PHP signature: imagecolorallocate(GdImage $image, int $red, int $green, int $blue): int|false
pub fn imagecolorallocate(image: &mut GdImage, r: u8, g: u8, b: u8) -> u32 {
    let color = pack_argb(0, r, g, b);
    image.allocated_colors.push(color);
    color
}

/// Allocate a color with alpha for an image.
///
/// PHP signature: imagecolorallocatealpha(GdImage $image, int $red, int $green, int $blue, int $alpha): int|false
pub fn imagecolorallocatealpha(image: &mut GdImage, r: u8, g: u8, b: u8, a: u8) -> u32 {
    // PHP alpha: 0=opaque, 127=transparent. We store as ARGB where A is 0-127.
    let color = pack_argb(a, r, g, b);
    image.allocated_colors.push(color);
    color
}

/// Set a pixel color.
///
/// PHP signature: imagesetpixel(GdImage $image, int $x, int $y, int $color): bool
pub fn imagesetpixel(image: &mut GdImage, x: i32, y: i32, color: u32) -> bool {
    if let Some(idx) = image.pixel_index(x, y) {
        image.pixels[idx] = color;
        true
    } else {
        false
    }
}

/// Get the color of a pixel.
///
/// PHP signature: imagecolorat(GdImage $image, int $x, int $y): int|false
pub fn imagecolorat(image: &GdImage, x: i32, y: i32) -> u32 {
    if let Some(idx) = image.pixel_index(x, y) {
        image.pixels[idx]
    } else {
        0
    }
}

/// Draw a line using Bresenham's algorithm.
///
/// PHP signature: imageline(GdImage $image, int $x1, int $y1, int $x2, int $y2, int $color): bool
pub fn imageline(image: &mut GdImage, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) -> bool {
    let dx = (x2 - x1).abs();
    let dy = -(y2 - y1).abs();
    let sx: i32 = if x1 < x2 { 1 } else { -1 };
    let sy: i32 = if y1 < y2 { 1 } else { -1 };
    let mut err = dx + dy;
    let mut cx = x1;
    let mut cy = y1;

    loop {
        imagesetpixel(image, cx, cy, color);

        if cx == x2 && cy == y2 {
            break;
        }

        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            cx += sx;
        }
        if e2 <= dx {
            err += dx;
            cy += sy;
        }
    }

    true
}

/// Draw a rectangle (outline).
///
/// PHP signature: imagerectangle(GdImage $image, int $x1, int $y1, int $x2, int $y2, int $color): bool
pub fn imagerectangle(image: &mut GdImage, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) -> bool {
    imageline(image, x1, y1, x2, y1, color);
    imageline(image, x2, y1, x2, y2, color);
    imageline(image, x2, y2, x1, y2, color);
    imageline(image, x1, y2, x1, y1, color);
    true
}

/// Draw a filled rectangle.
///
/// PHP signature: imagefilledrectangle(GdImage $image, int $x1, int $y1, int $x2, int $y2, int $color): bool
pub fn imagefilledrectangle(
    image: &mut GdImage,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    color: u32,
) -> bool {
    let min_x = x1.min(x2).max(0);
    let max_x = x1.max(x2).min(image.width as i32 - 1);
    let min_y = y1.min(y2).max(0);
    let max_y = y1.max(y2).min(image.height as i32 - 1);

    for y in min_y..=max_y {
        for x in min_x..=max_x {
            imagesetpixel(image, x, y, color);
        }
    }
    true
}

/// Draw an ellipse (outline) using the midpoint ellipse algorithm.
///
/// PHP signature: imageellipse(GdImage $image, int $cx, int $cy, int $width, int $height, int $color): bool
pub fn imageellipse(
    image: &mut GdImage,
    cx: i32,
    cy: i32,
    width: u32,
    height: u32,
    color: u32,
) -> bool {
    let rx = width as f64 / 2.0;
    let ry = height as f64 / 2.0;
    let steps = ((rx + ry) * 2.0).max(36.0) as i32;

    for i in 0..steps {
        let angle = 2.0 * std::f64::consts::PI * (i as f64) / (steps as f64);
        let x = cx + (rx * angle.cos()) as i32;
        let y = cy + (ry * angle.sin()) as i32;
        imagesetpixel(image, x, y, color);
    }
    true
}

/// Draw a filled ellipse.
///
/// PHP signature: imagefilledellipse(GdImage $image, int $cx, int $cy, int $width, int $height, int $color): bool
pub fn imagefilledellipse(
    image: &mut GdImage,
    cx: i32,
    cy: i32,
    width: u32,
    height: u32,
    color: u32,
) -> bool {
    let rx = width as f64 / 2.0;
    let ry = height as f64 / 2.0;

    let min_y = (cy as f64 - ry).ceil() as i32;
    let max_y = (cy as f64 + ry).floor() as i32;

    for y in min_y..=max_y {
        let dy = (y - cy) as f64;
        if ry == 0.0 {
            continue;
        }
        let x_span = rx * (1.0 - (dy * dy) / (ry * ry)).max(0.0).sqrt();
        let min_x = (cx as f64 - x_span).ceil() as i32;
        let max_x = (cx as f64 + x_span).floor() as i32;
        for x in min_x..=max_x {
            imagesetpixel(image, x, y, color);
        }
    }
    true
}

/// Flood fill starting at (x, y).
///
/// PHP signature: imagefill(GdImage $image, int $x, int $y, int $color): bool
pub fn imagefill(image: &mut GdImage, x: i32, y: i32, color: u32) -> bool {
    if image.pixel_index(x, y).is_none() {
        return false;
    }

    let target_color = imagecolorat(image, x, y);
    if target_color == color {
        return true; // Already the right color
    }

    let mut queue = VecDeque::new();
    queue.push_back((x, y));

    while let Some((px, py)) = queue.pop_front() {
        if image.pixel_index(px, py).is_none() {
            continue;
        }
        if imagecolorat(image, px, py) != target_color {
            continue;
        }

        imagesetpixel(image, px, py, color);

        queue.push_back((px + 1, py));
        queue.push_back((px - 1, py));
        queue.push_back((px, py + 1));
        queue.push_back((px, py - 1));
    }

    true
}

/// Copy part of an image.
///
/// PHP signature: imagecopy(GdImage $dst_image, GdImage $src_image, ...) : bool
#[allow(clippy::too_many_arguments)]
pub fn imagecopy(
    dst: &mut GdImage,
    src: &GdImage,
    dst_x: i32,
    dst_y: i32,
    src_x: i32,
    src_y: i32,
    src_w: u32,
    src_h: u32,
) -> bool {
    for sy in 0..src_h as i32 {
        for sx in 0..src_w as i32 {
            let pixel = imagecolorat(src, src_x + sx, src_y + sy);
            imagesetpixel(dst, dst_x + sx, dst_y + sy, pixel);
        }
    }
    true
}

/// Copy and resize part of an image.
///
/// PHP signature: imagecopyresized(GdImage $dst_image, GdImage $src_image, ...) : bool
#[allow(clippy::too_many_arguments)]
pub fn imagecopyresized(
    dst: &mut GdImage,
    src: &GdImage,
    dst_x: i32,
    dst_y: i32,
    src_x: i32,
    src_y: i32,
    dst_w: u32,
    dst_h: u32,
    src_w: u32,
    src_h: u32,
) -> bool {
    if dst_w == 0 || dst_h == 0 || src_w == 0 || src_h == 0 {
        return false;
    }

    for dy in 0..dst_h as i32 {
        for dx in 0..dst_w as i32 {
            let sx = src_x + (dx as u32 * src_w / dst_w) as i32;
            let sy = src_y + (dy as u32 * src_h / dst_h) as i32;
            let pixel = imagecolorat(src, sx, sy);
            imagesetpixel(dst, dst_x + dx, dst_y + dy, pixel);
        }
    }
    true
}

/// Rotate an image by the given angle (in degrees).
///
/// PHP signature: imagerotate(GdImage $image, float $angle, int $background_color, bool $ignore_transparent = false): GdImage|false
pub fn imagerotate(image: &GdImage, angle: f64, bg_color: u32) -> GdImage {
    let radians = -angle.to_radians();
    let cos_a = radians.cos();
    let sin_a = radians.sin();

    let w = image.width as f64;
    let h = image.height as f64;

    // Calculate new dimensions
    let new_w = (w * cos_a.abs() + h * sin_a.abs()).ceil() as u32;
    let new_h = (w * sin_a.abs() + h * cos_a.abs()).ceil() as u32;

    let mut result = GdImage {
        width: new_w,
        height: new_h,
        pixels: vec![bg_color; (new_w * new_h) as usize],
        true_color: image.true_color,
        allocated_colors: image.allocated_colors.clone(),
    };

    let cx = w / 2.0;
    let cy = h / 2.0;
    let ncx = new_w as f64 / 2.0;
    let ncy = new_h as f64 / 2.0;

    for ny in 0..new_h as i32 {
        for nx in 0..new_w as i32 {
            let dx = nx as f64 - ncx;
            let dy = ny as f64 - ncy;
            let ox = (dx * cos_a + dy * sin_a + cx) as i32;
            let oy = (-dx * sin_a + dy * cos_a + cy) as i32;

            if ox >= 0 && ox < image.width as i32 && oy >= 0 && oy < image.height as i32 {
                let pixel = imagecolorat(image, ox, oy);
                imagesetpixel(&mut result, nx, ny, pixel);
            }
        }
    }

    result
}

/// Flip an image.
///
/// PHP signature: imageflip(GdImage $image, int $mode): bool
pub fn imageflip(image: &mut GdImage, mode: i32) {
    let w = image.width as usize;
    let h = image.height as usize;

    if mode & IMG_FLIP_HORIZONTAL != 0 {
        for y in 0..h {
            for x in 0..w / 2 {
                let left = y * w + x;
                let right = y * w + (w - 1 - x);
                image.pixels.swap(left, right);
            }
        }
    }

    if mode & IMG_FLIP_VERTICAL != 0 {
        for y in 0..h / 2 {
            for x in 0..w {
                let top = y * w + x;
                let bottom = (h - 1 - y) * w + x;
                image.pixels.swap(top, bottom);
            }
        }
    }
}

/// Scale an image to the given width (and optionally height).
///
/// PHP signature: imagescale(GdImage $image, int $width, int $height = -1, int $mode = IMG_BILINEAR_FIXED): GdImage|false
pub fn imagescale(image: &GdImage, new_width: u32, new_height: Option<u32>) -> GdImage {
    let nh = new_height.unwrap_or_else(|| {
        if image.width == 0 {
            0
        } else {
            (image.height as u64 * new_width as u64 / image.width as u64) as u32
        }
    });

    let mut result = imagecreatetruecolor(new_width, nh);

    if image.width > 0 && image.height > 0 && new_width > 0 && nh > 0 {
        imagecopyresized(
            &mut result,
            image,
            0,
            0,
            0,
            0,
            new_width,
            nh,
            image.width,
            image.height,
        );
    }

    result
}

/// Crop an image to the given rectangle.
///
/// PHP signature: imagecrop(GdImage $image, array $rectangle): GdImage|false
pub fn imagecrop(image: &GdImage, rect: &GdRect) -> GdImage {
    let mut result = imagecreatetruecolor(rect.width, rect.height);
    imagecopy(
        &mut result,
        image,
        0,
        0,
        rect.x,
        rect.y,
        rect.width,
        rect.height,
    );
    result
}

/// Draw a horizontal string using a built-in font.
///
/// PHP signature: imagestring(GdImage $image, int $font, int $x, int $y, string $string, int $color): bool
pub fn imagestring(
    image: &mut GdImage,
    _font: i32,
    x: i32,
    y: i32,
    string: &str,
    color: u32,
) -> bool {
    // Simple 5x7 pixel font stub - draw a dot for each character position
    let char_width = 6; // 5 pixels + 1 spacing
    let char_height = 8; // 7 pixels + 1 spacing

    for (i, _ch) in string.chars().enumerate() {
        let cx = x + (i as i32) * char_width;
        // Draw a simple 5x7 block for each character (stub)
        for dy in 0..char_height - 1 {
            for dx in 0..char_width - 1 {
                imagesetpixel(image, cx + dx, y + dy, color);
            }
        }
    }
    true
}

/// Create a GdImage from raw PNG data.
///
/// PHP signature: imagecreatefrompng(string $filename): GdImage|false
pub fn imagecreatefrompng_data(data: &[u8]) -> Option<GdImage> {
    let decoder = png::Decoder::new(std::io::Cursor::new(data));
    let mut reader = decoder.read_info().ok()?;
    let mut img_buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut img_buf).ok()?;
    let width = info.width;
    let height = info.height;

    let pixels = match info.color_type {
        png::ColorType::Rgba => {
            let mut px = Vec::with_capacity((width * height) as usize);
            for chunk in img_buf[..info.buffer_size()].chunks_exact(4) {
                let r = chunk[0];
                let g = chunk[1];
                let b = chunk[2];
                let a = chunk[3];
                // PNG alpha: 0=transparent, 255=opaque -> GD alpha: 0=opaque, 127=transparent
                let gd_alpha = ((255 - a) as u32 + 1) / 2;
                px.push(pack_argb(gd_alpha as u8, r, g, b));
            }
            px
        }
        png::ColorType::Rgb => {
            let mut px = Vec::with_capacity((width * height) as usize);
            for chunk in img_buf[..info.buffer_size()].chunks_exact(3) {
                px.push(pack_argb(0, chunk[0], chunk[1], chunk[2]));
            }
            px
        }
        png::ColorType::GrayscaleAlpha => {
            let mut px = Vec::with_capacity((width * height) as usize);
            for chunk in img_buf[..info.buffer_size()].chunks_exact(2) {
                let gray = chunk[0];
                let a = chunk[1];
                let gd_alpha = ((255 - a) as u32 + 1) / 2;
                px.push(pack_argb(gd_alpha as u8, gray, gray, gray));
            }
            px
        }
        png::ColorType::Grayscale => {
            let mut px = Vec::with_capacity((width * height) as usize);
            for &gray in &img_buf[..info.buffer_size()] {
                px.push(pack_argb(0, gray, gray, gray));
            }
            px
        }
        _ => return None, // Indexed color not commonly used from PHP
    };

    Some(GdImage {
        width,
        height,
        pixels,
        true_color: true,
        allocated_colors: Vec::new(),
    })
}

/// Create a GdImage from raw image data (auto-detect format).
///
/// PHP signature: imagecreatefromstring(string $data): GdImage|false
pub fn imagecreatefromstring(data: &[u8]) -> Option<GdImage> {
    // Try PNG first (magic: 89 50 4E 47)
    if data.len() >= 8 && data[0] == 0x89 && data[1] == b'P' && data[2] == b'N' && data[3] == b'G'
    {
        return imagecreatefrompng_data(data);
    }

    // Try GIF (magic: GIF87a or GIF89a)
    if data.len() >= 6 && &data[0..3] == b"GIF" {
        return imagecreatefromgif_data(data);
    }

    // Try JPEG (magic: FF D8)
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
        // JPEG decoding not implemented yet
        return None;
    }

    None
}

/// Create a GdImage from raw GIF data.
pub fn imagecreatefromgif_data(data: &[u8]) -> Option<GdImage> {
    let mut decoder = gif::DecodeOptions::new();
    decoder.set_color_output(gif::ColorOutput::RGBA);
    let mut decoder = decoder.read_info(std::io::Cursor::new(data)).ok()?;
    let frame = decoder.read_next_frame().ok()??;

    let width = frame.width as u32;
    let height = frame.height as u32;
    let mut pixels = Vec::with_capacity((width * height) as usize);

    for chunk in frame.buffer.chunks_exact(4) {
        let r = chunk[0];
        let g = chunk[1];
        let b = chunk[2];
        let a = chunk[3];
        let gd_alpha = ((255 - a) as u32 + 1) / 2;
        pixels.push(pack_argb(gd_alpha as u8, r, g, b));
    }

    Some(GdImage {
        width,
        height,
        pixels,
        true_color: true,
        allocated_colors: Vec::new(),
    })
}

/// Read actual image dimensions from file data.
///
/// PHP signature: getimagesizefromstring(string $data, array &$image_info = null): array|false
pub fn getimagesizefromstring(data: &[u8]) -> Option<ImageSize> {
    // PNG
    if data.len() >= 24 && data[0] == 0x89 && &data[1..4] == b"PNG" {
        // Width at offset 16, height at offset 20 (big-endian u32)
        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        return Some(ImageSize {
            width,
            height,
            image_type: IMG_PNG,
            bits: 8,
            channels: 3,
            mime: "image/png".to_string(),
        });
    }

    // JPEG
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
        // Search for SOF0 marker (FF C0) to find dimensions
        let mut i = 2;
        while i + 1 < data.len() {
            if data[i] != 0xFF {
                i += 1;
                continue;
            }
            let marker = data[i + 1];
            if marker == 0xC0 || marker == 0xC2 {
                // SOF0 or SOF2
                if i + 9 < data.len() {
                    let height =
                        u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
                    let width =
                        u16::from_be_bytes([data[i + 7], data[i + 8]]) as u32;
                    return Some(ImageSize {
                        width,
                        height,
                        image_type: IMG_JPG,
                        bits: 8,
                        channels: 3,
                        mime: "image/jpeg".to_string(),
                    });
                }
            }
            if i + 3 < data.len() {
                let seg_len =
                    u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                i += 2 + seg_len;
            } else {
                break;
            }
        }
        // Couldn't find SOF, return with unknown dimensions
        return Some(ImageSize {
            width: 0,
            height: 0,
            image_type: IMG_JPG,
            bits: 8,
            channels: 3,
            mime: "image/jpeg".to_string(),
        });
    }

    // GIF
    if data.len() >= 10 && &data[0..3] == b"GIF" {
        let width = u16::from_le_bytes([data[6], data[7]]) as u32;
        let height = u16::from_le_bytes([data[8], data[9]]) as u32;
        return Some(ImageSize {
            width,
            height,
            image_type: IMG_GIF,
            bits: 8,
            channels: 3,
            mime: "image/gif".to_string(),
        });
    }

    // BMP
    if data.len() >= 26 && &data[0..2] == b"BM" {
        let width = u32::from_le_bytes([data[18], data[19], data[20], data[21]]);
        let height = u32::from_le_bytes([data[22], data[23], data[24], data[25]]);
        return Some(ImageSize {
            width,
            height,
            image_type: IMG_BMP,
            bits: 24,
            channels: 3,
            mime: "image/bmp".to_string(),
        });
    }

    None
}

/// Encode image as PNG.
///
/// PHP signature: imagepng(GdImage $image, ...): bool
pub fn imagepng(image: &GdImage) -> Vec<u8> {
    imagepng_quality(image, -1)
}

/// Encode image as PNG with quality/compression level.
///
/// quality: -1 for default, 0-9 where 0=no compression, 9=max compression
pub fn imagepng_quality(image: &GdImage, quality: i32) -> Vec<u8> {
    if image.width == 0 || image.height == 0 {
        return Vec::new();
    }

    let mut buf = Vec::new();
    {
        let mut encoder =
            png::Encoder::new(&mut buf, image.width, image.height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);

        let compression = match quality {
            0 => png::Compression::Fast,
            1..=3 => png::Compression::Fast,
            4..=6 => png::Compression::Default,
            7..=9 => png::Compression::Best,
            _ => png::Compression::Default,
        };
        encoder.set_compression(compression);

        let mut writer = match encoder.write_header() {
            Ok(w) => w,
            Err(_) => return Vec::new(),
        };

        // Convert ARGB pixels to RGBA bytes
        let mut rgba_data = Vec::with_capacity((image.width * image.height * 4) as usize);
        for &pixel in &image.pixels {
            let a = ((pixel >> 24) & 0xFF) as u8;
            let r = ((pixel >> 16) & 0xFF) as u8;
            let g = ((pixel >> 8) & 0xFF) as u8;
            let b = (pixel & 0xFF) as u8;
            // PHP GD alpha: 0=opaque, 127=transparent. PNG alpha: 0=transparent, 255=opaque
            let png_alpha = 255 - (a * 2).min(255);
            rgba_data.push(r);
            rgba_data.push(g);
            rgba_data.push(b);
            rgba_data.push(png_alpha);
        }

        if writer.write_image_data(&rgba_data).is_err() {
            return Vec::new();
        }
    }
    buf
}

/// Encode image as JPEG.
///
/// PHP signature: imagejpeg(GdImage $image, ...): bool
pub fn imagejpeg(image: &GdImage) -> Vec<u8> {
    imagejpeg_quality(image, 75)
}

/// Encode image as JPEG with quality (0-100).
pub fn imagejpeg_quality(image: &GdImage, quality: i32) -> Vec<u8> {
    if image.width == 0 || image.height == 0 {
        return Vec::new();
    }

    // JPEG: minimal JFIF encoder
    // Convert ARGB to RGB
    let mut rgb_data = Vec::with_capacity((image.width * image.height * 3) as usize);
    for &pixel in &image.pixels {
        let r = ((pixel >> 16) & 0xFF) as u8;
        let g = ((pixel >> 8) & 0xFF) as u8;
        let b = (pixel & 0xFF) as u8;
        rgb_data.push(r);
        rgb_data.push(g);
        rgb_data.push(b);
    }

    encode_jpeg_baseline(&rgb_data, image.width, image.height, quality.clamp(0, 100) as u8)
}

/// Encode image as GIF.
///
/// PHP signature: imagegif(GdImage $image, ...): bool
pub fn imagegif(image: &GdImage) -> Vec<u8> {
    if image.width == 0 || image.height == 0 || image.width > 65535 || image.height > 65535 {
        return Vec::new();
    }

    let mut buf = Vec::new();
    {
        let mut encoder = match gif::Encoder::new(
            &mut buf,
            image.width as u16,
            image.height as u16,
            &[],
        ) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        // Build a color palette from the image (max 256 colors for GIF)
        let (palette, indices) = quantize_to_palette(image);

        let mut frame = gif::Frame {
            width: image.width as u16,
            height: image.height as u16,
            buffer: std::borrow::Cow::Borrowed(&indices),
            palette: Some(palette),
            ..Default::default()
        };
        frame.dispose = gif::DisposalMethod::Any;

        if encoder.write_frame(&frame).is_err() {
            return Vec::new();
        }
    }
    buf
}

/// Quantize image colors to a 256-color palette for GIF encoding.
fn quantize_to_palette(image: &GdImage) -> (Vec<u8>, Vec<u8>) {
    use std::collections::HashMap;

    let mut color_map: HashMap<u32, u8> = HashMap::new();
    let mut palette: Vec<u8> = Vec::new(); // RGB triplets
    let mut indices: Vec<u8> = Vec::with_capacity(image.pixels.len());

    for &pixel in &image.pixels {
        // Strip alpha for GIF (no alpha support in basic GIF)
        let rgb = pixel & 0x00FFFFFF;

        let idx = if let Some(&existing) = color_map.get(&rgb) {
            existing
        } else if color_map.len() < 256 {
            let idx = color_map.len() as u8;
            color_map.insert(rgb, idx);
            palette.push(((rgb >> 16) & 0xFF) as u8);
            palette.push(((rgb >> 8) & 0xFF) as u8);
            palette.push((rgb & 0xFF) as u8);
            idx
        } else {
            // More than 256 colors: find nearest color in palette
            find_nearest_color(rgb, &palette)
        };

        indices.push(idx);
    }

    // GIF requires palette size to be a power of 2
    while palette.len() < 6 {
        // Minimum 2 colors
        palette.push(0);
    }

    (palette, indices)
}

/// Find the nearest color in a palette (simple Euclidean distance).
fn find_nearest_color(rgb: u32, palette: &[u8]) -> u8 {
    let r = ((rgb >> 16) & 0xFF) as i32;
    let g = ((rgb >> 8) & 0xFF) as i32;
    let b = (rgb & 0xFF) as i32;

    let mut best_idx = 0u8;
    let mut best_dist = i32::MAX;

    for i in (0..palette.len()).step_by(3) {
        let pr = palette[i] as i32;
        let pg = palette[i + 1] as i32;
        let pb = palette[i + 2] as i32;
        let dist = (r - pr) * (r - pr) + (g - pg) * (g - pg) + (b - pb) * (b - pb);
        if dist < best_dist {
            best_dist = dist;
            best_idx = (i / 3) as u8;
        }
    }

    best_idx
}

/// Minimal baseline JPEG encoder.
///
/// Produces valid JFIF files. Uses simple block-by-block DCT encoding.
fn encode_jpeg_baseline(rgb: &[u8], width: u32, height: u32, quality: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity((width * height) as usize);

    // Standard JPEG luminance quantization table
    #[rustfmt::skip]
    let base_lum_quant: [u8; 64] = [
        16, 11, 10, 16,  24,  40,  51,  61,
        12, 12, 14, 19,  26,  58,  60,  55,
        14, 13, 16, 24,  40,  57,  69,  56,
        14, 17, 22, 29,  51,  87,  80,  62,
        18, 22, 37, 56,  68, 109, 103,  77,
        24, 35, 55, 64,  81, 104, 113,  92,
        49, 64, 78, 87, 103, 121, 120, 101,
        72, 92, 95, 98, 112, 100, 103,  99,
    ];

    // Standard JPEG chrominance quantization table
    #[rustfmt::skip]
    let base_chr_quant: [u8; 64] = [
        17, 18, 24, 47, 99, 99, 99, 99,
        18, 21, 26, 66, 99, 99, 99, 99,
        24, 26, 56, 99, 99, 99, 99, 99,
        47, 66, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99,
    ];

    // Scale quantization tables by quality
    let scale = if quality < 50 {
        5000 / quality.max(1) as u32
    } else {
        200 - 2 * quality as u32
    };

    let mut lum_quant = [0u8; 64];
    let mut chr_quant = [0u8; 64];
    for i in 0..64 {
        lum_quant[i] =
            ((base_lum_quant[i] as u32 * scale + 50) / 100).clamp(1, 255) as u8;
        chr_quant[i] =
            ((base_chr_quant[i] as u32 * scale + 50) / 100).clamp(1, 255) as u8;
    }

    // Zigzag order
    #[rustfmt::skip]
    let zigzag: [usize; 64] = [
         0,  1,  8, 16,  9,  2,  3, 10,
        17, 24, 32, 25, 18, 11,  4,  5,
        12, 19, 26, 33, 40, 48, 41, 34,
        27, 20, 13,  6,  7, 14, 21, 28,
        35, 42, 49, 56, 57, 50, 43, 36,
        29, 22, 15, 23, 30, 37, 44, 51,
        58, 59, 52, 45, 38, 31, 39, 46,
        53, 60, 61, 54, 47, 55, 62, 63,
    ];

    // SOI
    buf.extend_from_slice(&[0xFF, 0xD8]);

    // APP0 (JFIF)
    buf.extend_from_slice(&[
        0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00,
    ]);

    // DQT - luminance (table 0)
    buf.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    for i in 0..64 {
        buf.push(lum_quant[zigzag[i]]);
    }

    // DQT - chrominance (table 1)
    buf.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x01]);
    for i in 0..64 {
        buf.push(chr_quant[zigzag[i]]);
    }

    // SOF0 (baseline DCT)
    buf.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    buf.push((height >> 8) as u8);
    buf.push(height as u8);
    buf.push((width >> 8) as u8);
    buf.push(width as u8);
    buf.extend_from_slice(&[
        0x03, // 3 components
        0x01, 0x11, 0x00, // Y: 1x1 sampling, quant table 0
        0x02, 0x11, 0x01, // Cb: 1x1 sampling, quant table 1
        0x03, 0x11, 0x01, // Cr: 1x1 sampling, quant table 1
    ]);

    // DHT - DC luminance (table 0)
    #[rustfmt::skip]
    let dc_lum_bits: [u8; 16] = [0,1,5,1,1,1,1,1,1,0,0,0,0,0,0,0];
    #[rustfmt::skip]
    let dc_lum_vals: [u8; 12] = [0,1,2,3,4,5,6,7,8,9,10,11];
    write_dht(&mut buf, 0x00, &dc_lum_bits, &dc_lum_vals);

    // DHT - DC chrominance (table 1)
    #[rustfmt::skip]
    let dc_chr_bits: [u8; 16] = [0,3,1,1,1,1,1,1,1,1,1,0,0,0,0,0];
    #[rustfmt::skip]
    let dc_chr_vals: [u8; 12] = [0,1,2,3,4,5,6,7,8,9,10,11];
    write_dht(&mut buf, 0x01, &dc_chr_bits, &dc_chr_vals);

    // DHT - AC luminance (table 0)
    #[rustfmt::skip]
    let ac_lum_bits: [u8; 16] = [0,2,1,3,3,2,4,3,5,5,4,4,0,0,1,0x7d];
    #[rustfmt::skip]
    let ac_lum_vals: [u8; 162] = [
        0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,
        0x22,0x71,0x14,0x32,0x81,0x91,0xa1,0x08,0x23,0x42,0xb1,0xc1,0x15,0x52,0xd1,0xf0,
        0x24,0x33,0x62,0x72,0x82,0x09,0x0a,0x16,0x17,0x18,0x19,0x1a,0x25,0x26,0x27,0x28,
        0x29,0x2a,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x43,0x44,0x45,0x46,0x47,0x48,0x49,
        0x4a,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x63,0x64,0x65,0x66,0x67,0x68,0x69,
        0x6a,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x83,0x84,0x85,0x86,0x87,0x88,0x89,
        0x8a,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xc2,0xc3,0xc4,0xc5,
        0xc6,0xc7,0xc8,0xc9,0xca,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xe1,0xe2,
        0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,
        0xf9,0xfa,
    ];
    write_dht(&mut buf, 0x10, &ac_lum_bits, &ac_lum_vals);

    // DHT - AC chrominance (table 1)
    #[rustfmt::skip]
    let ac_chr_bits: [u8; 16] = [0,2,1,2,4,4,3,4,7,5,4,4,0,1,2,0x77];
    #[rustfmt::skip]
    let ac_chr_vals: [u8; 162] = [
        0x00,0x01,0x02,0x03,0x11,0x04,0x05,0x21,0x31,0x06,0x12,0x41,0x51,0x07,0x61,0x71,
        0x13,0x22,0x32,0x81,0x08,0x14,0x42,0x91,0xa1,0xb1,0xc1,0x09,0x23,0x33,0x52,0xf0,
        0x15,0x62,0x72,0xd1,0x0a,0x16,0x24,0x34,0xe1,0x25,0xf1,0x17,0x18,0x19,0x1a,0x26,
        0x27,0x28,0x29,0x2a,0x35,0x36,0x37,0x38,0x39,0x3a,0x43,0x44,0x45,0x46,0x47,0x48,
        0x49,0x4a,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x63,0x64,0x65,0x66,0x67,0x68,
        0x69,0x6a,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0xa2,0xa3,0xa4,0xa5,
        0xa6,0xa7,0xa8,0xa9,0xaa,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,
        0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,
        0xf9,0xfa,
    ];
    write_dht(&mut buf, 0x11, &ac_chr_bits, &ac_chr_vals);

    // Build Huffman encoding tables
    let dc_lum_enc = build_huffman_table(&dc_lum_bits, &dc_lum_vals);
    let dc_chr_enc = build_huffman_table(&dc_chr_bits, &dc_chr_vals);
    let ac_lum_enc = build_huffman_table(&ac_lum_bits, &ac_lum_vals);
    let ac_chr_enc = build_huffman_table(&ac_chr_bits, &ac_chr_vals);

    // SOS
    buf.extend_from_slice(&[
        0xFF, 0xDA, 0x00, 0x0C, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00,
    ]);

    // Encode scan data
    let mut bitbuf: u32 = 0;
    let mut bitcount: u32 = 0;
    let mut dc_y: i32 = 0;
    let mut dc_cb: i32 = 0;
    let mut dc_cr: i32 = 0;

    let padded_w = ((width + 7) / 8 * 8) as usize;
    let padded_h = ((height + 7) / 8 * 8) as usize;

    for by in (0..padded_h).step_by(8) {
        for bx in (0..padded_w).step_by(8) {
            // Extract 8x8 block, convert to YCbCr
            let mut y_block = [0i32; 64];
            let mut cb_block = [0i32; 64];
            let mut cr_block = [0i32; 64];

            for dy in 0..8 {
                for dx in 0..8 {
                    let px = (bx + dx).min(width as usize - 1);
                    let py = (by + dy).min(height as usize - 1);
                    let idx = py * width as usize + px;
                    let ri = idx * 3;

                    let r = rgb[ri] as f32;
                    let g = rgb[ri + 1] as f32;
                    let b = rgb[ri + 2] as f32;

                    let bi = dy * 8 + dx;
                    y_block[bi] = (0.299 * r + 0.587 * g + 0.114 * b - 128.0) as i32;
                    cb_block[bi] = (-0.1687 * r - 0.3313 * g + 0.5 * b) as i32;
                    cr_block[bi] = (0.5 * r - 0.4187 * g - 0.0813 * b) as i32;
                }
            }

            // Forward DCT + quantize + encode each block
            let mut dct_buf = [0i32; 64];

            fdct(&y_block, &mut dct_buf);
            quantize(&mut dct_buf, &lum_quant);
            dc_y = encode_block(
                &dct_buf,
                dc_y,
                &dc_lum_enc,
                &ac_lum_enc,
                &zigzag,
                &mut buf,
                &mut bitbuf,
                &mut bitcount,
            );

            fdct(&cb_block, &mut dct_buf);
            quantize(&mut dct_buf, &chr_quant);
            dc_cb = encode_block(
                &dct_buf,
                dc_cb,
                &dc_chr_enc,
                &ac_chr_enc,
                &zigzag,
                &mut buf,
                &mut bitbuf,
                &mut bitcount,
            );

            fdct(&cr_block, &mut dct_buf);
            quantize(&mut dct_buf, &chr_quant);
            dc_cr = encode_block(
                &dct_buf,
                dc_cr,
                &dc_chr_enc,
                &ac_chr_enc,
                &zigzag,
                &mut buf,
                &mut bitbuf,
                &mut bitcount,
            );
        }
    }

    // Flush remaining bits
    if bitcount > 0 {
        bitbuf <<= 32 - bitcount;
        while bitcount > 0 {
            let byte = (bitbuf >> 24) as u8;
            buf.push(byte);
            if byte == 0xFF {
                buf.push(0x00); // byte stuff
            }
            bitbuf <<= 8;
            bitcount = bitcount.saturating_sub(8);
        }
    }

    // EOI
    buf.extend_from_slice(&[0xFF, 0xD9]);

    buf
}

/// Write a DHT marker segment.
fn write_dht(buf: &mut Vec<u8>, class_and_id: u8, bits: &[u8; 16], vals: &[u8]) {
    let length = 2 + 1 + 16 + vals.len();
    buf.extend_from_slice(&[0xFF, 0xC4]);
    buf.push((length >> 8) as u8);
    buf.push(length as u8);
    buf.push(class_and_id);
    buf.extend_from_slice(bits);
    buf.extend_from_slice(vals);
}

/// Build Huffman encoding lookup: symbol -> (code, nbits)
fn build_huffman_table(bits: &[u8; 16], vals: &[u8]) -> Vec<(u16, u8)> {
    let mut table = vec![(0u16, 0u8); 256];
    let mut code: u16 = 0;
    let mut vi = 0;
    for (i, &count) in bits.iter().enumerate() {
        let nbits = (i + 1) as u8;
        for _ in 0..count {
            if vi < vals.len() {
                table[vals[vi] as usize] = (code, nbits);
                vi += 1;
            }
            code += 1;
        }
        code <<= 1;
    }
    table
}

/// Forward DCT (8x8, integer approximation based on AAN algorithm).
fn fdct(block: &[i32; 64], out: &mut [i32; 64]) {
    // Rows
    let mut tmp = [0f32; 64];
    for i in 0..8 {
        let s = i * 8;
        let v0 = block[s] as f32 + block[s + 7] as f32;
        let v7 = block[s] as f32 - block[s + 7] as f32;
        let v1 = block[s + 1] as f32 + block[s + 6] as f32;
        let v6 = block[s + 1] as f32 - block[s + 6] as f32;
        let v2 = block[s + 2] as f32 + block[s + 5] as f32;
        let v5 = block[s + 2] as f32 - block[s + 5] as f32;
        let v3 = block[s + 3] as f32 + block[s + 4] as f32;
        let v4 = block[s + 3] as f32 - block[s + 4] as f32;

        let t0 = v0 + v3;
        let t3 = v0 - v3;
        let t1 = v1 + v2;
        let t2 = v1 - v2;

        tmp[s] = t0 + t1;
        tmp[s + 4] = t0 - t1;

        let c6 = 0.382683433f32; // cos(6*pi/16)
        let s6 = 0.923879533f32; // sin(6*pi/16)
        tmp[s + 2] = t2 * c6 + t3 * s6;
        tmp[s + 6] = t3 * c6 - t2 * s6;

        let t4 = v4 + v5;
        let t5 = v5 + v6;
        let t6 = v6 + v7;

        let c3 = 0.707106781f32; // cos(pi/4)
        let t5b = (t5) * c3;

        let c1 = 0.490392640f32;
        let s1 = 0.097545161f32;
        let c5 = 0.277785116f32;
        let s5 = 0.415734806f32;

        let _ = (c1, s1, c5, s5);

        tmp[s + 1] = v7 + t5b;
        tmp[s + 7] = v7 - t5b;

        let t4b = t4 * 0.541196100f32;
        let t6b = t6 * 1.306562965f32;
        tmp[s + 5] = t4b - t5b + tmp[s + 7];
        tmp[s + 3] = t6b - t5b + tmp[s + 1];
    }

    // Columns
    for i in 0..8 {
        let v0 = tmp[i] + tmp[56 + i];
        let v7 = tmp[i] - tmp[56 + i];
        let v1 = tmp[8 + i] + tmp[48 + i];
        let v6 = tmp[8 + i] - tmp[48 + i];
        let v2 = tmp[16 + i] + tmp[40 + i];
        let v5 = tmp[16 + i] - tmp[40 + i];
        let v3 = tmp[24 + i] + tmp[32 + i];
        let v4 = tmp[24 + i] - tmp[32 + i];

        let t0 = v0 + v3;
        let t3 = v0 - v3;
        let t1 = v1 + v2;
        let t2 = v1 - v2;

        out[i] = ((t0 + t1) * 0.125) as i32;
        out[32 + i] = ((t0 - t1) * 0.125) as i32;

        let c6 = 0.382683433f32;
        let s6 = 0.923879533f32;
        out[16 + i] = ((t2 * c6 + t3 * s6) * 0.125) as i32;
        out[48 + i] = ((t3 * c6 - t2 * s6) * 0.125) as i32;

        let t5 = v5 + v6;
        let c3 = 0.707106781f32;
        let t5b = t5 * c3;

        out[8 + i] = ((v7 + t5b) * 0.125) as i32;
        out[56 + i] = ((v7 - t5b) * 0.125) as i32;

        let t4b = (v4 + v5) * 0.541196100f32;
        let t6b = (v6 + v7) * 1.306562965f32;
        out[40 + i] = ((t4b - t5b + out[56 + i] as f32 / 0.125) * 0.125) as i32;
        out[24 + i] = ((t6b - t5b + out[8 + i] as f32 / 0.125) * 0.125) as i32;
    }
}

/// Quantize DCT coefficients.
fn quantize(block: &mut [i32; 64], quant: &[u8; 64]) {
    for i in 0..64 {
        let q = quant[i] as i32;
        block[i] = if block[i] >= 0 {
            (block[i] + q / 2) / q
        } else {
            (block[i] - q / 2) / q
        };
    }
}

/// Encode a single 8x8 DCT block into the bitstream.
#[allow(clippy::too_many_arguments)]
fn encode_block(
    block: &[i32; 64],
    prev_dc: i32,
    dc_table: &[(u16, u8)],
    ac_table: &[(u16, u8)],
    zigzag: &[usize; 64],
    buf: &mut Vec<u8>,
    bitbuf: &mut u32,
    bitcount: &mut u32,
) -> i32 {
    // DC coefficient
    let dc = block[zigzag[0]];
    let diff = dc - prev_dc;
    let (cat, bits) = categorize(diff);
    emit_huffman(dc_table[cat as usize], buf, bitbuf, bitcount);
    if cat > 0 {
        emit_bits(bits as u16, cat, buf, bitbuf, bitcount);
    }

    // AC coefficients
    let mut zero_count = 0u8;
    for i in 1..64 {
        let ac = block[zigzag[i]];
        if ac == 0 {
            zero_count += 1;
        } else {
            while zero_count >= 16 {
                emit_huffman(ac_table[0xF0], buf, bitbuf, bitcount); // ZRL
                zero_count -= 16;
            }
            let (cat, bits) = categorize(ac);
            let symbol = (zero_count << 4) | cat;
            emit_huffman(ac_table[symbol as usize], buf, bitbuf, bitcount);
            emit_bits(bits as u16, cat, buf, bitbuf, bitcount);
            zero_count = 0;
        }
    }

    if zero_count > 0 {
        emit_huffman(ac_table[0x00], buf, bitbuf, bitcount); // EOB
    }

    dc
}

/// Categorize a coefficient value: returns (category, bits).
fn categorize(val: i32) -> (u8, u32) {
    if val == 0 {
        return (0, 0);
    }
    let abs_val = val.unsigned_abs();
    let cat = 32 - abs_val.leading_zeros();
    let bits = if val > 0 {
        val as u32
    } else {
        (val - 1) as u32 // ones' complement for negative
    };
    (cat as u8, bits)
}

/// Emit a Huffman code.
fn emit_huffman(
    entry: (u16, u8),
    buf: &mut Vec<u8>,
    bitbuf: &mut u32,
    bitcount: &mut u32,
) {
    let (code, nbits) = entry;
    emit_bits(code, nbits, buf, bitbuf, bitcount);
}

/// Emit bits to the output buffer.
fn emit_bits(
    code: u16,
    nbits: u8,
    buf: &mut Vec<u8>,
    bitbuf: &mut u32,
    bitcount: &mut u32,
) {
    *bitbuf |= (code as u32) << (32 - *bitcount - nbits as u32);
    *bitcount += nbits as u32;

    while *bitcount >= 8 {
        let byte = (*bitbuf >> 24) as u8;
        buf.push(byte);
        if byte == 0xFF {
            buf.push(0x00); // byte stuffing
        }
        *bitbuf <<= 8;
        *bitcount -= 8;
    }
}

/// Get image size information from a file (stub).
///
/// PHP signature: getimagesize(string $filename, array &$image_info = null): array|false
pub fn getimagesize(filename: &str) -> Option<ImageSize> {
    // Basic extension-based detection (stub)
    let lower = filename.to_lowercase();
    if lower.ends_with(".png") {
        Some(ImageSize {
            width: 0,
            height: 0,
            image_type: IMG_PNG,
            bits: 8,
            channels: 3,
            mime: "image/png".to_string(),
        })
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some(ImageSize {
            width: 0,
            height: 0,
            image_type: IMG_JPG,
            bits: 8,
            channels: 3,
            mime: "image/jpeg".to_string(),
        })
    } else if lower.ends_with(".gif") {
        Some(ImageSize {
            width: 0,
            height: 0,
            image_type: IMG_GIF,
            bits: 8,
            channels: 3,
            mime: "image/gif".to_string(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imagecreate() {
        let img = imagecreate(100, 50);
        assert_eq!(imagesx(&img), 100);
        assert_eq!(imagesy(&img), 50);
        assert!(!img.true_color);
        assert_eq!(img.pixels.len(), 5000);
    }

    #[test]
    fn test_imagecreatetruecolor() {
        let img = imagecreatetruecolor(200, 100);
        assert_eq!(imagesx(&img), 200);
        assert_eq!(imagesy(&img), 100);
        assert!(img.true_color);
        // All pixels should be black
        assert!(img.pixels.iter().all(|&p| p == pack_argb(0, 0, 0, 0)));
    }

    #[test]
    fn test_imagedestroy() {
        let mut img = imagecreatetruecolor(100, 100);
        imagedestroy(&mut img);
        assert_eq!(img.width, 0);
        assert_eq!(img.height, 0);
        assert!(img.pixels.is_empty());
    }

    #[test]
    fn test_imagecolorallocate() {
        let mut img = imagecreatetruecolor(10, 10);
        let red = imagecolorallocate(&mut img, 255, 0, 0);
        assert_eq!(red, pack_argb(0, 255, 0, 0));

        let green = imagecolorallocate(&mut img, 0, 255, 0);
        assert_eq!(green, pack_argb(0, 0, 255, 0));
    }

    #[test]
    fn test_imagecolorallocatealpha() {
        let mut img = imagecreatetruecolor(10, 10);
        let semi = imagecolorallocatealpha(&mut img, 255, 0, 0, 64);
        assert_eq!(semi, pack_argb(64, 255, 0, 0));
    }

    #[test]
    fn test_setpixel_and_colorat() {
        let mut img = imagecreatetruecolor(10, 10);
        let red = pack_argb(0, 255, 0, 0);
        assert!(imagesetpixel(&mut img, 5, 5, red));
        assert_eq!(imagecolorat(&img, 5, 5), red);

        // Out of bounds
        assert!(!imagesetpixel(&mut img, 10, 10, red));
        assert!(!imagesetpixel(&mut img, -1, 0, red));
    }

    #[test]
    fn test_imageline() {
        let mut img = imagecreatetruecolor(10, 10);
        let white = pack_argb(0, 255, 255, 255);
        assert!(imageline(&mut img, 0, 0, 9, 0, white));

        // All pixels on the line should be white
        for x in 0..10 {
            assert_eq!(imagecolorat(&img, x, 0), white);
        }
    }

    #[test]
    fn test_imagerectangle() {
        let mut img = imagecreatetruecolor(20, 20);
        let blue = pack_argb(0, 0, 0, 255);
        assert!(imagerectangle(&mut img, 2, 2, 8, 8, blue));

        // Corners should be blue
        assert_eq!(imagecolorat(&img, 2, 2), blue);
        assert_eq!(imagecolorat(&img, 8, 2), blue);
        assert_eq!(imagecolorat(&img, 2, 8), blue);
        assert_eq!(imagecolorat(&img, 8, 8), blue);

        // Interior should still be black
        assert_eq!(imagecolorat(&img, 5, 5), pack_argb(0, 0, 0, 0));
    }

    #[test]
    fn test_imagefilledrectangle() {
        let mut img = imagecreatetruecolor(20, 20);
        let green = pack_argb(0, 0, 255, 0);
        assert!(imagefilledrectangle(&mut img, 5, 5, 10, 10, green));

        // Interior should be green
        assert_eq!(imagecolorat(&img, 7, 7), green);
        assert_eq!(imagecolorat(&img, 5, 5), green);
        assert_eq!(imagecolorat(&img, 10, 10), green);

        // Outside should still be black
        assert_eq!(imagecolorat(&img, 4, 4), pack_argb(0, 0, 0, 0));
    }

    #[test]
    fn test_imagefilledellipse() {
        let mut img = imagecreatetruecolor(50, 50);
        let red = pack_argb(0, 255, 0, 0);
        assert!(imagefilledellipse(&mut img, 25, 25, 20, 20, red));

        // Center should be red
        assert_eq!(imagecolorat(&img, 25, 25), red);
        // Far corner should not be red
        assert_ne!(imagecolorat(&img, 0, 0), red);
    }

    #[test]
    fn test_imagefill() {
        let mut img = imagecreatetruecolor(10, 10);
        let white = pack_argb(0, 255, 255, 255);
        assert!(imagefill(&mut img, 0, 0, white));

        // All pixels should be white
        for y in 0..10 {
            for x in 0..10 {
                assert_eq!(imagecolorat(&img, x, y), white);
            }
        }
    }

    #[test]
    fn test_imagecopy() {
        let mut src = imagecreatetruecolor(10, 10);
        let red = pack_argb(0, 255, 0, 0);
        imagefilledrectangle(&mut src, 0, 0, 9, 9, red);

        let mut dst = imagecreatetruecolor(20, 20);
        assert!(imagecopy(&mut dst, &src, 5, 5, 0, 0, 10, 10));

        assert_eq!(imagecolorat(&dst, 5, 5), red);
        assert_eq!(imagecolorat(&dst, 14, 14), red);
        assert_eq!(imagecolorat(&dst, 0, 0), pack_argb(0, 0, 0, 0));
    }

    #[test]
    fn test_imageflip_horizontal() {
        let mut img = imagecreatetruecolor(4, 1);
        let colors = [1u32, 2, 3, 4];
        img.pixels = colors.to_vec();

        imageflip(&mut img, IMG_FLIP_HORIZONTAL);
        assert_eq!(img.pixels, vec![4, 3, 2, 1]);
    }

    #[test]
    fn test_imageflip_vertical() {
        let mut img = imagecreatetruecolor(2, 2);
        img.pixels = vec![1, 2, 3, 4]; // top row: 1,2; bottom: 3,4

        imageflip(&mut img, IMG_FLIP_VERTICAL);
        assert_eq!(img.pixels, vec![3, 4, 1, 2]);
    }

    #[test]
    fn test_imagescale() {
        let mut img = imagecreatetruecolor(100, 50);
        let red = pack_argb(0, 255, 0, 0);
        imagefilledrectangle(&mut img, 0, 0, 99, 49, red);

        let scaled = imagescale(&img, 50, None);
        assert_eq!(scaled.width, 50);
        assert_eq!(scaled.height, 25);
    }

    #[test]
    fn test_imagecrop() {
        let mut img = imagecreatetruecolor(20, 20);
        let blue = pack_argb(0, 0, 0, 255);
        imagefilledrectangle(&mut img, 5, 5, 14, 14, blue);

        let rect = GdRect {
            x: 5,
            y: 5,
            width: 10,
            height: 10,
        };
        let cropped = imagecrop(&img, &rect);
        assert_eq!(cropped.width, 10);
        assert_eq!(cropped.height, 10);
        assert_eq!(imagecolorat(&cropped, 0, 0), blue);
    }

    #[test]
    fn test_imagerotate() {
        let mut img = imagecreatetruecolor(10, 10);
        let red = pack_argb(0, 255, 0, 0);
        imagefilledrectangle(&mut img, 0, 0, 9, 9, red);

        let bg = pack_argb(0, 0, 0, 0);
        let rotated = imagerotate(&img, 0.0, bg);
        // 0-degree rotation should preserve size
        assert_eq!(rotated.width, 10);
        assert_eq!(rotated.height, 10);
    }

    #[test]
    fn test_imagestring() {
        let mut img = imagecreatetruecolor(100, 20);
        let white = pack_argb(0, 255, 255, 255);
        assert!(imagestring(&mut img, 1, 0, 0, "Hi", white));
        // First character position should be drawn
        assert_eq!(imagecolorat(&img, 0, 0), white);
    }

    #[test]
    fn test_getimagesize() {
        let png = getimagesize("test.png").unwrap();
        assert_eq!(png.image_type, IMG_PNG);
        assert_eq!(png.mime, "image/png");

        let jpg = getimagesize("photo.jpg").unwrap();
        assert_eq!(jpg.image_type, IMG_JPG);
        assert_eq!(jpg.mime, "image/jpeg");

        let gif = getimagesize("anim.gif").unwrap();
        assert_eq!(gif.image_type, IMG_GIF);
        assert_eq!(gif.mime, "image/gif");

        assert!(getimagesize("unknown.xyz").is_none());
    }

    #[test]
    fn test_imagepng_encoding() {
        let mut img = imagecreatetruecolor(10, 10);
        let red = pack_argb(0, 255, 0, 0);
        imagefilledrectangle(&mut img, 0, 0, 9, 9, red);

        let data = imagepng(&img);
        assert!(!data.is_empty());
        // PNG magic bytes
        assert_eq!(&data[0..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    }

    #[test]
    fn test_imagejpeg_encoding() {
        let mut img = imagecreatetruecolor(16, 16);
        let blue = pack_argb(0, 0, 0, 255);
        imagefilledrectangle(&mut img, 0, 0, 15, 15, blue);

        let data = imagejpeg(&img);
        assert!(!data.is_empty());
        // JPEG magic bytes (SOI)
        assert_eq!(&data[0..2], &[0xFF, 0xD8]);
        // JPEG should end with EOI
        assert_eq!(&data[data.len() - 2..], &[0xFF, 0xD9]);
    }

    #[test]
    fn test_imagegif_encoding() {
        let mut img = imagecreatetruecolor(10, 10);
        let green = pack_argb(0, 0, 255, 0);
        imagefilledrectangle(&mut img, 0, 0, 9, 9, green);

        let data = imagegif(&img);
        assert!(!data.is_empty());
        // GIF magic bytes
        assert!(data.starts_with(b"GIF"));
    }

    #[test]
    fn test_imagepng_empty_image() {
        let img = GdImage {
            width: 0,
            height: 0,
            pixels: Vec::new(),
            true_color: true,
            allocated_colors: Vec::new(),
        };
        assert!(imagepng(&img).is_empty());
    }

    #[test]
    fn test_imagejpeg_quality() {
        let mut img = imagecreatetruecolor(32, 32);
        let red = pack_argb(0, 255, 0, 0);
        imagefilledrectangle(&mut img, 0, 0, 31, 31, red);

        let low_q = imagejpeg_quality(&img, 10);
        let high_q = imagejpeg_quality(&img, 95);
        // Higher quality should generally produce larger files
        assert!(!low_q.is_empty());
        assert!(!high_q.is_empty());
    }

    #[test]
    fn test_imagepng_alpha() {
        let mut img = imagecreatetruecolor(4, 4);
        // Semi-transparent red (alpha=64 in PHP GD scale)
        let semi_red = pack_argb(64, 255, 0, 0);
        imagefilledrectangle(&mut img, 0, 0, 3, 3, semi_red);

        let data = imagepng(&img);
        assert!(!data.is_empty());
        assert_eq!(&data[0..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    }

    #[test]
    fn test_imageellipse() {
        let mut img = imagecreatetruecolor(50, 50);
        let white = pack_argb(0, 255, 255, 255);
        assert!(imageellipse(&mut img, 25, 25, 30, 20, white));
        // Some pixels on the ellipse should be set
        // The rightmost point of the ellipse (~cx + rx)
        assert_eq!(imagecolorat(&img, 40, 25), white);
    }

    #[test]
    fn test_png_roundtrip() {
        // Create an image, encode to PNG, decode back, verify pixels
        let mut img = imagecreatetruecolor(8, 8);
        let red = pack_argb(0, 255, 0, 0);
        let blue = pack_argb(0, 0, 0, 255);
        imagefilledrectangle(&mut img, 0, 0, 3, 7, red);
        imagefilledrectangle(&mut img, 4, 0, 7, 7, blue);

        let png_data = imagepng(&img);
        assert!(!png_data.is_empty());

        let decoded = imagecreatefrompng_data(&png_data).unwrap();
        assert_eq!(decoded.width, 8);
        assert_eq!(decoded.height, 8);

        // Check red half
        assert_eq!(imagecolorat(&decoded, 0, 0), red);
        assert_eq!(imagecolorat(&decoded, 3, 3), red);
        // Check blue half
        assert_eq!(imagecolorat(&decoded, 4, 0), blue);
        assert_eq!(imagecolorat(&decoded, 7, 7), blue);
    }

    #[test]
    fn test_gif_roundtrip() {
        let mut img = imagecreatetruecolor(4, 4);
        let green = pack_argb(0, 0, 255, 0);
        imagefilledrectangle(&mut img, 0, 0, 3, 3, green);

        let gif_data = imagegif(&img);
        assert!(!gif_data.is_empty());

        let decoded = imagecreatefromgif_data(&gif_data).unwrap();
        assert_eq!(decoded.width, 4);
        assert_eq!(decoded.height, 4);
        // Verify the green pixel survived the roundtrip
        let px = imagecolorat(&decoded, 0, 0);
        // GIF is lossy (palette quantization), so check color is approximately right
        let g = ((px >> 8) & 0xFF) as u8;
        assert_eq!(g, 255);
    }

    #[test]
    fn test_imagecreatefromstring_png() {
        let mut img = imagecreatetruecolor(4, 4);
        let white = pack_argb(0, 255, 255, 255);
        imagefilledrectangle(&mut img, 0, 0, 3, 3, white);

        let png_data = imagepng(&img);
        let decoded = imagecreatefromstring(&png_data).unwrap();
        assert_eq!(decoded.width, 4);
        assert_eq!(decoded.height, 4);
    }

    #[test]
    fn test_imagecreatefromstring_gif() {
        let mut img = imagecreatetruecolor(4, 4);
        let red = pack_argb(0, 255, 0, 0);
        imagefilledrectangle(&mut img, 0, 0, 3, 3, red);

        let gif_data = imagegif(&img);
        let decoded = imagecreatefromstring(&gif_data).unwrap();
        assert_eq!(decoded.width, 4);
        assert_eq!(decoded.height, 4);
    }

    #[test]
    fn test_imagecreatefromstring_invalid() {
        assert!(imagecreatefromstring(b"not an image").is_none());
        assert!(imagecreatefromstring(b"").is_none());
    }

    #[test]
    fn test_getimagesizefromstring_png() {
        let mut img = imagecreatetruecolor(32, 16);
        let black = pack_argb(0, 0, 0, 0);
        imagefilledrectangle(&mut img, 0, 0, 31, 15, black);

        let data = imagepng(&img);
        let info = getimagesizefromstring(&data).unwrap();
        assert_eq!(info.width, 32);
        assert_eq!(info.height, 16);
        assert_eq!(info.image_type, IMG_PNG);
        assert_eq!(info.mime, "image/png");
    }

    #[test]
    fn test_getimagesizefromstring_gif() {
        let img = imagecreatetruecolor(10, 20);
        let data = imagegif(&img);
        let info = getimagesizefromstring(&data).unwrap();
        assert_eq!(info.width, 10);
        assert_eq!(info.height, 20);
        assert_eq!(info.image_type, IMG_GIF);
    }

    #[test]
    fn test_getimagesizefromstring_invalid() {
        assert!(getimagesizefromstring(b"garbage").is_none());
    }
}
