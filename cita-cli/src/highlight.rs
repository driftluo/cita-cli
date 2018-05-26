use ansi_term::Colour::{Fixed, RGB};
use ansi_term::Style;
use syntect::dumps::from_binary;
use syntect::easy::HighlightLines;
use syntect::highlighting::ThemeSet;
use syntect::highlighting::{self, FontStyle};
use syntect::parsing::SyntaxSet;

/// Approximate a 24 bit color value by a 8 bit ANSI code
fn rgb2ansi(r: u8, g: u8, b: u8) -> u8 {
    const BLACK: u8 = 16;
    const WHITE: u8 = 231;

    if r == g && g == b {
        if r < 8 {
            BLACK
        } else if r > 248 {
            WHITE
        } else {
            let fr = f32::from(r);
            (((fr - 8.) / 247.) * 24.) as u8 + 232
        }
    } else {
        let fr = f32::from(r);
        let fg = f32::from(g);
        let fb = f32::from(b);
        16 + (36 * (fr / 255. * 5.) as u8) + (6 * (fg / 255. * 5.) as u8) + (fb / 255. * 5.) as u8
    }
}

pub fn as_terminal_escaped(
    style: highlighting::Style,
    text: &str,
    true_color: bool,
    colored: bool,
) -> String {
    let style = if !colored {
        Style::default()
    } else {
        let color = if true_color {
            RGB(style.foreground.r, style.foreground.g, style.foreground.b)
        } else {
            let ansi = rgb2ansi(style.foreground.r, style.foreground.g, style.foreground.b);
            Fixed(ansi)
        };

        if style.font_style.contains(FontStyle::BOLD) {
            color.bold()
        } else if style.font_style.contains(FontStyle::UNDERLINE) {
            color.underline()
        } else if style.font_style.contains(FontStyle::ITALIC) {
            color.italic()
        } else {
            color.normal()
        }
    };

    style.paint(text).to_string()
}

pub fn highlight(content: &str, language: &str) -> String {
    let mut syntax_set: SyntaxSet = from_binary(include_bytes!("../assets/syntaxes.bin"));
    syntax_set.link_syntaxes();
    let theme_set: ThemeSet = from_binary(include_bytes!("../assets/themes.bin"));
    let syntax = syntax_set.find_syntax_by_token(language).unwrap();
    let theme = theme_set.themes.get("Default").unwrap();

    let mut highlighter = HighlightLines::new(syntax, theme);
    let ranges = highlighter.highlight(content);
    ranges
        .iter()
        .map(|&(style, text)| as_terminal_escaped(style, text, true, true))
        .collect::<Vec<_>>()
        .join("")
}
