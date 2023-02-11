use std::{thread, time::{Duration, Instant}};

use probe::probe;


fn main() {
    // let d = Duration::from_secs(1);
    let mut i = 0;
    loop {
        let t0 = Instant::now();
        probe!(hello_provider, hello, i);
        // println!("Hello, world! {}", i);
        println!("loop took {} ns", t0.elapsed().as_nanos());
        i += 1;
    }
}
