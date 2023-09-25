// use hello_world::greeter_client::GreeterClient;
// use hello_world::HelloRequest;

// pub mod hello_world {
//     tonic::include_proto!("helloworld");
// }

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = GreeterClient::connect("http://[::1]:50051").await?;

//     let request = tonic::Request::new(HelloRequest {
//         name: "Tonic".into(),
//     });

//     let response = client.say_hello(request).await?;

//     println!("RESPONSE={:?}", response);

//     Ok(())
    
// }


use std::fs;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // /home/jyr/work/narwhal-proj/sui/narwhal/benchmark/.committee.json
    let filepath = "../sui/narwhal/benchmark/.committee.json";
    let data = fs::read_to_string(filepath)?;

    let json: Value = serde_json::from_str(&data)?;

    // println!("{:#?}", json);
    let authorities  = json.get("authorities").and_then(Value::as_object);

    match authorities {
        Some(authorities) => {
            let keys: Vec<_> = authorities.keys().enumerate().collect();
            for (index, key) in keys {
                println!("{}\t{}", index, key);
            }
            // println!("{:?}", keys);   
        }
        None => println!("authorities field is not an object or doesn't exist"),
    }

    Ok(())
}