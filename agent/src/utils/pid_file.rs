/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use log::{debug, trace};
use nix::{sys::signal::kill, unistd::Pid};

static HANDLE: OnceLock<Mutex<Option<PidFile>>> = OnceLock::new();

pub fn open<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let file = PidFile::open(path)?;
    // 将pid文件设置到全局变量中
    if let Err(_) = HANDLE.set(Mutex::new(Some(file))) {
        debug!("pid file already opened");
    }
    Ok(())
}
// 关闭agent时手动销毁pid文件
pub fn close() {
    match HANDLE.get() {
        Some(h) => {
            // drop PidFile
            h.lock().unwrap().take();
        }
        None => debug!("pid file not set"),
    }
}

struct PidFile {
    path: PathBuf,
    fp: Option<File>,
}

impl PidFile {
    fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();
        trace!("check {} for existing pid file", path.display());
        // 读取pid文件内容
        match fs::read_to_string(path) {
            // 文件存在，说明之前启动过agent
            Ok(pid_str) => match pid_str.trim().parse::<u32>() {
                // check process
                // 检测agent进程是否存在
                Ok(pid) if kill(Pid::from_raw(pid as i32), None).is_ok() => {
                    // 如果是，直接返回错误
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "pid file exists with a running process",
                    ));
                }
                // 进程不存在，是上一次agent异常退出留下的遗留文件，忽略，继续启动
                _ => trace!("no process found with pid {}", pid_str),
            },
            // 文件不存在
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                trace!("old pid file {} not exist", path.display())
            }
            // 其他错误直接返回错误
            Err(e) => return Err(e),
        }
        // create pid file
        if let Some(parent) = path.parent() {
            // 防止父文件夹不存在
            fs::create_dir_all(parent)?;
        }
        // 创建文件
        let mut fp = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        // 写入agent进程的pid
        let pid = std::process::id();
        write!(fp, "{}\n", pid)?;
        // 实际完成写内容
        fp.sync_data()?;
        trace!(
            "pid file {} created and pid {} written",
            path.display(),
            pid
        );
        Ok(Self {
            path: path.to_owned(),
            fp: Some(fp),
        })
    }
}

impl Drop for PidFile {
    // agent退出时，自动释放pid文件句柄
    fn drop(&mut self) {
        std::mem::drop(self.fp.take());
        let _ = fs::remove_file(&self.path);
    }
}
