use tfhe::odd::prelude::*;

use std::fs::File;
use std::io::{BufRead, BufReader};


// A structure implementing the parsing of a "circuit file" from the papers and executing the circuit with the appropriate containers
pub struct LinearCircuit{
    pub x : Vec<Ciphertext>,    // the inputs
    pub t : Vec<Ciphertext>,    // the intermedary values
    pub y : Vec<Ciphertext>     // the outputs
}


impl LinearCircuit {
    pub fn new(state_slice: &Vec<Ciphertext>) -> Self{
        Self { x: state_slice.to_vec(), t: vec![], y: vec![] }
    }


    // the file of the circuit should contain on the first line N(inputs) Offset(Inputs) N(Intermediary) Offset(Intermediary) N(Output) Offset(output)
    pub fn execute_circuit(&mut self, server_key : &ServerKey, file_path : &str, client_key_debug : &ClientKey){
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let header: Vec<usize> = lines.next().unwrap().unwrap().split_whitespace().map(|n| n.parse::<usize>().unwrap()).collect();
        
        //check and dimensioning of the containers
        assert_eq!(self.x.len(), header[0]);
        self.t = vec![Ciphertext::Trivial(0);header[2]];
        self.y = vec![Ciphertext::Trivial(0);header[4]];
        let (offset_x, offset_t, offset_y) = (header[1], header[3], header[5]);

        for line in lines {
            let elmts:Vec<String> = line.unwrap().split_whitespace().map(|s| s.to_string()).collect::<Vec<String>>();
            let op1 = if elmts[2].contains('x'){    &self.x[elmts[2][1..].parse::<usize>().unwrap() - offset_x]    }
                                  else if elmts[2].contains('t'){   &self.t[elmts[2][1..].parse::<usize>().unwrap() - offset_t]    }
                                  else if elmts[2].contains('y'){   &self.y[elmts[2][1..].parse::<usize>().unwrap() - offset_y]    }
                                  else {panic!()};
            let op2 = if elmts[4].contains('x'){    &self.x[elmts[4][1..].parse::<usize>().unwrap() - offset_x]    }
                                  else if elmts[4].contains('t'){   &self.t[elmts[4][1..].parse::<usize>().unwrap() - offset_t]    }
                                  else if elmts[4].contains('y'){   &self.y[elmts[4][1..].parse::<usize>().unwrap() - offset_y]    }
                                  else {    panic!()    };
            if elmts[0].contains('y'){    
                self.y[elmts[0][1..].parse::<usize>().unwrap() - offset_y] = server_key.simple_sum(&vec![op1.to_owned(), op2.to_owned()]);
                if elmts[3] == "XNOR" {
                    self.y[elmts[0][1..].parse::<usize>().unwrap() - offset_y] = server_key.simple_plaintext_sum(&self.y[elmts[0][1..].parse::<usize>().unwrap()] , 1, 2);
                }
            }
            else if elmts[0].contains('t'){  
                self.t[elmts[0][1..].parse::<usize>().unwrap() - offset_t] = server_key.simple_sum(&vec![op1.to_owned(), op2.to_owned()]);
                if elmts[3] == "XNOR" {
                    self.t[elmts[0][1..].parse::<usize>().unwrap() - offset_t] = server_key.simple_plaintext_sum(&self.t[elmts[0][1..].parse::<usize>().unwrap()- offset_t] , 1, 2);
                }                
            }
            else {panic!()} 
        }
    }
}