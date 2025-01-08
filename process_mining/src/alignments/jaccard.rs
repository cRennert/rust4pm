use hashbag::HashBag;
use ndarray::prelude::*;
use ndarray::OwnedRepr;
use std::{cmp, fmt};
use std::collections::HashSet;
use std::fmt::Formatter;
use std::ops::Deref;

fn jaccard_similarity(set_a: &HashBag<&str>, set_b: &HashBag<&str>) -> f64 {
    let join: HashSet<(&&str, usize, usize)> = set_a.outer_join(&set_b).collect();
    let mut intersection_size = 0;
    let mut union_size = 0;
    join.iter().for_each(|(_, x, y)| {
        intersection_size += x.min(y);
        union_size += x.max(y);
    });

    intersection_size as f64 / union_size as f64
}

fn average_jaccard_similarity(bags: &Vec<(HashBag<&str>, HashBag<&str>)>) -> f64 {
    let mut results: Vec<f64> = Vec::new();
    for i in 0..bags.len() {
        results.push(jaccard_similarity(&bags[i].0, &bags[i].1));
    }
    results.iter().sum::<f64>() / (bags.len() as f64)
}

#[derive(Clone, Debug, Copy)]
enum Directions {
    // BothUpAndLeft,
    Up,
    Left,
    UpLeft,
    Neutral,
}

impl fmt::Display for Directions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self{
            Directions::Up => {write!(f, "\\uparrow")}
            Directions::Left => {write!(f, "\\leftarrow")}
            Directions::UpLeft => {write!(f, "\\nwarrow")}
            Directions::Neutral => {write!(f, "")}
        }
    }
}

fn compute_needleman_wunsch<'a>(
    list_1: &Vec<HashBag<&'a str>>,
    list_2: &Vec<HashBag<&'a str>>,
) -> (
    ArrayBase<OwnedRepr<f64>, Ix2>,
    ArrayBase<OwnedRepr<Directions>, Ix2>,
    Vec<(HashBag<&'a str>, HashBag<&'a str>)>,
) {
    let matrix_shape = (list_1.len() + 1, list_2.len() + 1);
    let mut values: ArrayBase<OwnedRepr<f64>, Ix2> = Array2::<f64>::zeros(matrix_shape);
    let mut directions: ArrayBase<OwnedRepr<Directions>, Ix2> =
        Array2::<Directions>::from_elem(matrix_shape, Directions::Neutral);
    for i in 1..list_1.len() + 1 {
        values[[i, 0]] = -(i as f64);
        directions[[i, 0]] = Directions::Up;
    }

    for i in 1..list_2.len() + 1 {
        values[[0, i]] = -(i as f64);
        directions[[0, i]] = Directions::Left;
    }

    for i in 1..list_1.len() + 1 {
        for j in 1..list_2.len() + 1 {
            compute_needleman_wunsch_at_pos(list_1, list_2, &mut values, &mut directions, (i, j));
        }
    }

    let best_alignment = compute_best_alignment(list_1, list_2, &directions);

    (values, directions, best_alignment)
}

fn compute_best_alignment<'a>(
    list_1: &Vec<HashBag<&'a str>>,
    list_2: &Vec<HashBag<&'a str>>,
    directions: &ArrayBase<OwnedRepr<Directions>, Ix2>,
) -> Vec<(HashBag<&'a str>, HashBag<&'a str>)> {
    let mut result_reversed: Vec<(HashBag<&'a str>, HashBag<&'a str>)> = Vec::new();
    let mut curr_pos = (list_1.len(), list_2.len());
    while curr_pos != (0, 0) {
        match directions[curr_pos] {
            Directions::Up => {
                result_reversed.push((list_1[curr_pos.0 - 1].clone(), HashBag::new()));
                curr_pos.0 = (curr_pos.0 as u32 - 1) as usize;
            }
            Directions::Left => {
                result_reversed.push((HashBag::new(), list_2[curr_pos.1 - 1].clone()));
                curr_pos.1 = (curr_pos.1 as u32 - 1) as usize;
            }
            Directions::UpLeft => {
                result_reversed.push((
                    list_1[curr_pos.0 - 1].clone(),
                    list_2[curr_pos.1 - 1].clone(),
                ));
                curr_pos.0 = (curr_pos.0 as u32 - 1) as usize;
                curr_pos.1 = (curr_pos.1 as u32 - 1) as usize;
            }
            Directions::Neutral => {
                break;
            }
            // Directions::BothUpAndLeft => {
            //     result_reversed.push((list_1[curr_pos.0 - 1].clone(), HashBag::new()));
            //     curr_pos.0 = (curr_pos.0 as u32 - 1) as usize;
            // }
        }
    }

    result_reversed.reverse();
    result_reversed
}

fn compute_needleman_wunsch_at_pos(
    list_1: &Vec<HashBag<&str>>,
    list_2: &Vec<HashBag<&str>>,
    values: &mut ArrayBase<OwnedRepr<f64>, Ix2>,
    directions: &mut ArrayBase<OwnedRepr<Directions>, Ix2>,
    pos: (usize, usize),
) {
    let similarity = jaccard_similarity(&list_1[pos.0 - 1], &list_2[pos.1 - 1]);

    let val_left = values[[pos.0, pos.1 - 1]] - 1.0;
    let val_up = values[[pos.0 - 1, pos.1]] - 1.0;
    
    let overview: [(Directions, f64); 3] = [
        // (Directions::BothUpAndLeft, (val_up + val_left) / 2.0 + 0.000001),
        (Directions::Up, val_up),
        (
            Directions::UpLeft,
            values[[pos.0 - 1, pos.1 - 1]] + (2.0 * similarity) - 1.0,
        ),
        (Directions::Left, val_left),
    ];

    let minimal_element: (Directions, f64) = overview
        .into_iter()
        .max_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap())
        .unwrap();

    directions[pos] = minimal_element.0;
    values[pos] = minimal_element.1;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let mut list_1: Vec<HashBag<&str>> = Vec::new();
        let mut list_2: Vec<HashBag<&str>> = Vec::new();
        let mut list_3: Vec<HashBag<&str>> = Vec::new();

        let mut list_4: Vec<HashBag<&str>> = Vec::new();
        list_4.push(["C01"].iter().cloned().collect());
        list_4.push(["C02"].iter().cloned().collect());
        list_4.push(["C03"].iter().cloned().collect());
        list_4.push(["C04"].iter().cloned().collect());
        list_4.push(["C05"].iter().cloned().collect());

        let mut list_5: Vec<HashBag<&str>> = Vec::new();
        // list_5.push(["C01"].iter().cloned().collect());
        // list_5.push(["C02"].iter().cloned().collect());
        // list_5.push(["C02"].iter().cloned().collect());
        // list_5.push(["C03"].iter().cloned().collect());
        // list_5.push(["C04"].iter().cloned().collect());
        // list_5.push(["C05"].iter().cloned().collect());
        list_5.push(["C02"].iter().cloned().collect());
        list_5.push(["C04"].iter().cloned().collect());
        list_5.push(["C06"].iter().cloned().collect());
        list_5.push(["C05"].iter().cloned().collect());
        list_5.push(["C03"].iter().cloned().collect());
        
        
        
        
        
        
        
        
        
        
        
        
        

        list_1.push(["C02", "C16", "C14", "C20"].iter().cloned().collect());
        list_1.push(["C03", "C15", "C22", "C23"].iter().cloned().collect());
        list_1.push(["C04", "C05", "C18"].iter().cloned().collect());
        list_1.push(["C01", "C01", "C06", "C12"].iter().cloned().collect());

        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        list_2.push(["C19", "C16", "C21", "C20"].iter().cloned().collect());
        list_2.push(["C22", "C23"].iter().cloned().collect());
        list_2.push(["C03", "C15"].iter().cloned().collect());
        list_2.push(["C02", "C04", "C05", "C18"].iter().cloned().collect());
        list_2.push(
            ["C01", "C01", "C06", "C12", "C13"]
                .iter()
                .cloned()
                .collect(),
        );

        list_3.push(
            ["C02", "C19", "C16", "C21", "C20"]
                .iter()
                .cloned()
                .collect(),
        );
        list_3.push(
            ["C03", "C15", "C17", "C22", "C23"]
                .iter()
                .cloned()
                .collect(),
        );
        list_3.push(
            ["C19", "C04", "C21", "C05", "C18"]
                .iter()
                .cloned()
                .collect(),
        );
        list_3.push(
            ["C01", "C01", "C06", "C12", "C23"]
                .iter()
                .cloned()
                .collect(),
        );

        // let mut values: ArrayBase<OwnedRepr<f64>, Ix2> = Array2::<f64>::zeros((5, 5));
        // let mut directions: ArrayBase<OwnedRepr<Directions>, Ix2> =
        Array2::<Directions>::from_elem((5, 5), Directions::Neutral);

        let (values, directions, best_alignment) = compute_needleman_wunsch(&list_1, &list_2);
        // compute_needleman_wunsch(&list_1, &list_2, &mut values, &mut directions);

        let average_jaccard = average_jaccard_similarity(&best_alignment);

        println!("{:?}", values);
        println!("{:?}", directions.to_string());
        println!("{:?}", best_alignment);
        println!("{:?}", average_jaccard);
    }
}
