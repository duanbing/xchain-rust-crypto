use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub enum Language {
    ChineseSimplified = 1,
    English,
}

lazy_static! {
    static ref WORDLIST_S_CH: WordMap = { load_wordlist(include_str!("langs/simplified_chinese.txt")) };
    static ref WORDLIST_EN: WordMap = { load_wordlist(include_str!("langs/english.txt")) };
}

struct WordMap {
    i2w: HashMap<u32, String>,
    w2i: HashMap<String, u32>,
}

fn load_wordlist(lang_words: &'static str) -> WordMap {
    let mut m = HashMap::new();
    let mut m2 = HashMap::new();

    let inner: Vec<_> = lang_words.split_whitespace().collect();
    debug_assert!(inner.len() == 2048, "Invalid wordlist length");

    let mut idx = 0;
    for line in inner {
        m.insert(idx, line.to_owned());
        m2.insert(line.to_owned(), idx);
        idx += 1;
    }
    WordMap { i2w: m, w2i: m2 }
}

// TODO 语言不存在判断
pub fn get_word_list_by_langs(l: Language) -> &'static HashMap<u32, String> {
    match l {
        Language::ChineseSimplified => &WORDLIST_S_CH.i2w,
        Language::English => &WORDLIST_EN.i2w,
    }
}

pub fn get_reversed_word_list_by_langs(l: Language) -> &'static HashMap<String, u32> {
    match l {
        Language::ChineseSimplified => &WORDLIST_S_CH.w2i,
        Language::English => &WORDLIST_EN.w2i,
    }
}
