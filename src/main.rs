
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use hyper_util::rt::TokioIo;


use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;


use serde::Serialize;
use serde::Deserialize;
use std::time::{SystemTime,UNIX_EPOCH};
use std::sync::Arc;
use sqlite::{State,Connection};

use bitcoin::consensus;
use bitcoin::Transaction;
use bitcoin::Network;

use hex_conservative::FromHex;
use regex::Regex;

#[derive(Debug, Serialize, Deserialize)]
struct MyConfig {
    address: String,
    fixed_fee: u64,
    bind: String,
    bind_port: u16,
    requests_file: String,
    db_file: String

}

impl Default for MyConfig {
    fn default() -> Self {
        MyConfig {
            address: "Unknown".to_string(),
            fixed_fee: 10000,
            bind:"127.0.0.1".to_string(),
            bind_port:9137,
            requests_file:"rawrequests.log".to_string(),
            db_file: "../bal.db".to_string()
        }
    }
}

async fn echo_info(
                   param: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        //let whole_body = req.collect().await?.to_bytes();
        println!("echo info!!!{}",param);
        if param  == "regtest"{
            return Ok(Response::new(full("{\"address\":\"bcrt1qzwtth3feqpzyq7kkn46xpautw07rnzk62vyelk\",\"base_fee\":\"100000\"}")));
        }
        Ok(Response::new(full("{\"address\":\"wrong param\",\"base_fee\":\"100000\"}")))
        //Err(Response::new(full("{\"address\":\"wrong\",\"base_fee\":\"100000\"}")))
            
}
async fn echo_push(whole_body: &Bytes,
                   cfg: &MyConfig,
                   param: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        //let whole_body = req.collect().await?.to_bytes();
        let strbody = std::str::from_utf8(&whole_body).unwrap();
        let lines = strbody.split("\n");
        let file = cfg.requests_file.to_string();
        //if !Path::new(&file).exists() {
        //    File::create(&file).unwrap();
        //}
        let network = match param{
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            &_ => Network::Bitcoin,
        };
        let req_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_nanos();
        
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(file)
            .unwrap();
    
        
        let mut sqltxs = "INSERT INTO tbl_tx (txid, wtxid, ntxid, tx, locktime, reqid, network)".to_string();
        let mut sqlinps = "INSERT INTO tbl_input (txid, in_txid,in_vout)".to_string();
        let mut sqlouts = "INSERT INTO tbl_output (txid, script_pubkey, address, amount)\n".to_string();
        let mut union_tx = true;
        let mut union_inps = true;
        let mut union_outs = true;
        let db = sqlite::open(&cfg.db_file).unwrap();
        for line in lines {
            let linea = format!("{req_time}:{line}");
            println!("New Tx: {}", linea);
            if let Err(e) = writeln!(file, "{}",linea) {
                eprintln!("Couldn't write to file: {}", e);
            }
            let raw_tx =  match Vec::<u8>::from_hex(line) {
                Ok(raw_tx) => raw_tx,
                Err(_) => continue,
            };
            //dbg!(&raw_tx);
            let tx: Transaction = match consensus::deserialize(&raw_tx){
                Ok(tx) => tx,
                Err(err) => {println!("error: unable to parse tx: {}\n{}",line,err);continue}
            };
            let txid = tx.txid().to_string();
            
            let mut statement = db.prepare("SELECT * FROM tbl_tx WHERE txid = ?").unwrap();
            statement.bind((1,&txid[..])).unwrap();
            //statement.bind((1,"Bob")).unwrap();
            if let Ok(State::Row) = statement.next() {
                continue;
            }
            let ntxid = tx.ntxid();
            let wtxid = tx.wtxid();
            let locktime = tx.lock_time;
            if !union_tx {
                sqltxs = format!("{sqltxs} UNION ALL");
            }else{
                union_tx = false;
            }
                sqltxs = format!("{sqltxs}  SELECT '{txid}', '{wtxid}', '{ntxid}', '{line}', '{locktime}', '{req_time}', '{network}'");

            
            for input in tx.input{
                if !union_inps{
                    sqlinps = format!("{sqlinps} UNION ALL");
                }else{
                    union_inps = false;
                }
                let in_txid = input.previous_output.txid;
                let in_vout = input.previous_output.vout;
                dbg!(input.sequence.is_rbf());

                sqlinps = format!("{sqlinps} SELECT \"{txid}\", \"{in_txid}\",\"{in_vout}\"");
            }
            for output in tx.output{
                if !union_outs {
                    sqlouts = format!("{sqlouts} UNION ALL");
                }else{
                    union_outs=false;
                }
                let script_pubkey = output.script_pubkey;
                let address = match bitcoin::Address::from_script(script_pubkey.as_script(), network){
                    Ok(address) => address.to_string(),
                    Err(_) => String::new(),
                };
                    
                let amount = output.value;
                sqlouts = format!("{sqlouts} SELECT \"{txid}\", \"{script_pubkey}\", \"{address}\", \"{amount}\"\n");

            }


        }
        let _ = db.execute("BEGIN TRANSACTION");
        let mut error = false;
        if let Err(_) = db.execute(sqltxs){
            let _ = db.execute("ROLLBACK");
            error = true;
        }
        if !error {
            if let Err(_) = db.execute(sqlinps){
                let _ = db.execute("ROLLBACK");
                error = true
            }
        }
        if !error {
            if let Err(_) = db.execute(sqlouts){
                let _ = db.execute("ROLLBACK");
                error = true;
            }
        }
        if !error {
            let _ = db.execute("COMMIT");
        }


        Ok(Response::new(full("thx")))

} 
fn create_database(db: Connection){
    println!("database sanity check");
    let _ = db.execute("CREATE TABLE IF NOT EXISTS tbl_tx      (txid PRIMARY KEY, wtxid, ntxid, tx, locktime integer, network, network_fees, reqid, fees, status integer DEFAULT 0);");
    let _ = db.execute("CREATE TABLE IF NOT EXISTS tbl_input   (txid, in_txid,in_vout, spend_txidi);");
    let _ = db.execute("CREATE TABLE IF NOT EXISTS tbl_output  (txid, script_pubkey, address, amount);");

    let _ = db.execute("CREATE UNIQUE INDEX idx_tbl_input   ON(txid, txid,in_txid,in_vout)");

}



fn match_uri<'a>(path: &str, uri: &'a str) -> Option<&'a str> {
    let re = Regex::new(path).unwrap();
    if let Some(captures) = re.captures(uri) {
        if let Some(param) = captures.name("param") {
            return Some(param.as_str());
        }
    }
    None
}

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.

async fn echo(
    req: Request<hyper::body::Incoming>,
    cfg: &MyConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {

    let mut not_found = Response::new(empty());
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    let mut ret: Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> = Ok(not_found);

    let uri = req.uri().path().to_string();
    //dbg!(&req);
    match req.method() {
        // Serve some instructions at /
        &Method::POST => {
            let whole_body = req.collect().await?.to_bytes();
            if let Some(param) = match_uri(r"^?/?(?P<param>[^/]?+)?/pushtxs$",uri.as_str()) {
                    ret = echo_push(&whole_body,cfg,param).await;
            }
                       ret
        }
        &Method::GET => {
            //let whole_body = req.collect().await?.to_bytes();
            if let Some(param) = match_uri(r"^?/?(?P<param>[^/]?+)?/info$",uri.as_str()) {
                   // ret = echo_info(&whole_body,cfg,param).await;
                    ret = echo_info(param).await;
            }

            ret
        }

        // Return the 404 Not Found for other routes.
        _ => {Ok(Response::new(full("ok")))}
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg: Arc<MyConfig> = Arc::new(confy::load("bal-server",None).expect("cant_load"));
    let file = confy::get_configuration_file_path("bal-server",None).expect("Error while getting path");
    let db = sqlite::open(&cfg.db_file).unwrap();
    create_database(db);
    {
        //let cfg = Arc::clone(&cfg);
        //thread::spawn(move|| {
            //let cfg = Arc::clone(&cfg);
            //let file = cfg.requests_file.to_string();
            //loop{
            //        let input = File::open(&file)?;
            //        let reader = BufReader::new(input);


            //        for line in lines.flatten(){
            //           // println!("{}",line);
            //        }
                 
            //thread::sleep(Duration::from_secs(2));
            //}
        //});
    }

    println!("The configuration file path is: {:#?}", file);


    let addr = cfg.bind.to_string();
    let addr: IpAddr = addr.parse()?;

    let listener = TcpListener::bind((addr,cfg.bind_port)).await?;
    println!("Listening on http://{}:{}", addr,cfg.bind_port);
            
    

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        
       tokio::task::spawn({
            let cfg = Arc::clone(&cfg);
            async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service_fn(|req: Request<hyper::body::Incoming>| async {
                        echo(req,&cfg).await
                    }))
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }

            }
        });
    }
}
