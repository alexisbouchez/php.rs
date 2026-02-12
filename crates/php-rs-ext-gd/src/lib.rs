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

/// Encode image as PNG (stub - returns empty Vec).
///
/// PHP signature: imagepng(GdImage $image, ...): bool
pub fn imagepng(_image: &GdImage) -> Vec<u8> {
    // Stub: PNG encoding not implemented
    Vec::new()
}

/// Encode image as JPEG (stub - returns empty Vec).
///
/// PHP signature: imagejpeg(GdImage $image, ...): bool
pub fn imagejpeg(_image: &GdImage) -> Vec<u8> {
    // Stub: JPEG encoding not implemented
    Vec::new()
}

/// Encode image as GIF (stub - returns empty Vec).
///
/// PHP signature: imagegif(GdImage $image, ...): bool
pub fn imagegif(_image: &GdImage) -> Vec<u8> {
    // Stub: GIF encoding not implemented
    Vec::new()
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
    fn test_image_encoding_stubs() {
        let img = imagecreatetruecolor(10, 10);
        assert!(imagepng(&img).is_empty());
        assert!(imagejpeg(&img).is_empty());
        assert!(imagegif(&img).is_empty());
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
}
