use crate::{
    protocol::{read_frame, write_frame, Request, Response, RpcError},
    Host,
};
use serde_json::{json, Value};
use std::{io, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{broadcast, mpsc, oneshot, Semaphore},
    task::JoinSet,
};

pub async fn serve<S>(host: Arc<Host>, stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_until(host, stream, std::future::pending()).await
}

pub async fn serve_until<S, F>(host: Arc<Host>, stream: S, cancellation: F) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: std::future::Future<Output = ()> + Send,
{
    tokio::pin!(cancellation);
    let (reader, writer) = tokio::io::split(stream);
    let (outgoing, responses) = mpsc::channel::<(Value, Option<oneshot::Sender<()>>)>(64);
    let (closed, mut closed_rx) = mpsc::channel(1);
    let mut writer_task = tokio::spawn(write_messages(
        writer,
        responses,
        host.subscribe_events(),
        host.subscribe_bulk(),
    ));
    let mut logs = host.log_sender().subscribe();
    let log_host = Arc::clone(&host);
    let log_task = tokio::spawn(async move {
        loop {
            match logs.recv().await {
                Ok(log) => log_host.forward_log(&log),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    let mut reader = reader;
    let mut requests = JoinSet::new();
    let capacity = Arc::new(Semaphore::new(64));
    let payload_budget = Arc::new(Semaphore::new(crate::protocol::MAX_FRAME_SIZE));
    let outcome = {
        let read_requests = async {
            loop {
                tokio::select! {
                    completed=requests.join_next(),if !requests.is_empty()=>{if let Some(Err(e))=completed {tracing::warn!("RPC request ended: {e}");}},
                    frame=read_frame(&mut reader)=>{
                        let frame=match frame {Ok(Some(frame))=>frame,Ok(None)=>break Ok(()),Err(e)=>break Err(e)};
                        let payload = Arc::clone(&payload_budget).try_acquire_many_owned(frame.len().try_into().map_err(io::Error::other)?);
                        let request=match serde_json::from_slice::<Request>(&frame) {
                            Ok(request)=>request,
                            Err(error)=>{
                                let response=Response {id:None,result:Value::Null,error:Some(RpcError::new("invalid_request",error.to_string()))};
                                if outgoing.send((serde_json::to_value(response).map_err(io::Error::other)?,None)).await.is_err() {break Err(io::Error::new(io::ErrorKind::BrokenPipe,"IPC writer exited"));}
                                continue;
                            }
                        };
                        let Ok(payload) = payload else {
                            let response=Response{id:request.id,result:Value::Null,error:Some(RpcError::new("busy","Pending RPC payload budget exhausted"))};
                            if outgoing.send((serde_json::to_value(response).map_err(io::Error::other)?,None)).await.is_err() {break Err(io::Error::new(io::ErrorKind::BrokenPipe,"IPC writer exited"));}
                            continue;
                        };
                        let Ok(permit)=Arc::clone(&capacity).try_acquire_owned() else {
                                let response=Response{id:request.id,result:Value::Null,error:Some(RpcError::new("busy","Too many pending RPC requests"))};
                                if outgoing.send((serde_json::to_value(response).map_err(io::Error::other)?,None)).await.is_err() {break Err(io::Error::new(io::ErrorKind::BrokenPipe,"IPC writer exited"));}
                                continue;
                        };
                        let host=Arc::clone(&host);let outgoing=outgoing.clone();let closed=closed.clone();
                        requests.spawn(async move {
                            let shutdown=request.method=="shutdown";
                            let response=host.call(request).await;
                            if shutdown && response.error.is_none() {
                                let(ack,received)=oneshot::channel();
                                if let Ok(value)=serde_json::to_value(response) {let _=outgoing.send((value,Some(ack))).await;}
                                let _=received.await;let _=closed.send(()).await;
                            }else if let Ok(value)=serde_json::to_value(response) {let _=outgoing.send((value,None)).await;}
                            drop(permit);
                            drop(payload);
                        });
                    }
                }
            }
        };
        tokio::pin!(read_requests);
        tokio::select! {
            _=&mut cancellation=>Ok(()),
            result=&mut writer_task=>result.unwrap_or_else(|error|Err(io::Error::other(error))),
            _=closed_rx.recv()=>Ok(()),
            result=&mut read_requests=>result,
        }
    };
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    log_task.abort();
    writer_task.abort();
    let _ = log_task.await;
    if !writer_task.is_finished() {
        let _ = writer_task.await;
    }
    host.shutdown().await.map_err(io::Error::other)?;
    outcome
}

async fn write_messages<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut responses: mpsc::Receiver<(Value, Option<oneshot::Sender<()>>)>,
    mut events: broadcast::Receiver<Value>,
    mut bulk: broadcast::Receiver<Value>,
) -> io::Result<()> {
    loop {
        let (value, ack) = tokio::select! {
            biased;
            response=responses.recv()=>match response {Some(response)=>response,None=>return Ok(())},
            event=events.recv()=>match event {Ok(event)=>(json!({"method":"message","arguments":[event]}),None),Err(broadcast::error::RecvError::Lagged(_))=>continue,Err(broadcast::error::RecvError::Closed)=>return Ok(())},
            event=bulk.recv()=>match event {Ok(event)=>(json!({"method":"message","arguments":[event]}),None),Err(broadcast::error::RecvError::Lagged(_))=>continue,Err(broadcast::error::RecvError::Closed)=>return Ok(())},
        };
        let frame = serde_json::to_vec(&value).map_err(io::Error::other)?;
        write_frame(&mut writer, &frame).await?;
        if let Some(ack) = ack {
            let _ = ack.send(());
        }
    }
}
