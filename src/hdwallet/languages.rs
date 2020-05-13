use std::collections::HashMap;

use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub enum Language {
    ChineseSimplified = 1,
    English,
}

lazy_static! {
    static ref WORDLIST_S_CH: WordMap = { load_wordlist("./langs/simplified_chinese.txt") };
    static ref WORDLIST_EN: WordMap = { load_wordlist("./langs/english.txt") };
}

struct WordMap {
    i2w: HashMap<u32, String>,
    w2i: HashMap<String, u32>,
}

//TODO 改成直接加载文件
fn load_wordlist(filename: &str) -> WordMap {
    let mut m = HashMap::new();
    let mut m2 = HashMap::new();
    let default_path = std::env::var("LANGS").unwrap_or("".to_string());
    let base_path = Path::new(&default_path);
    let path = base_path.join(PathBuf::from(filename));
    let file = File::open(path).expect("can not open file");
    let reader = BufReader::new(file);

    let mut idx = 0;
    for line in reader.lines() {
        let line = line.unwrap();
        m.insert(idx, line.to_owned());
        m2.insert(line, idx);
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
