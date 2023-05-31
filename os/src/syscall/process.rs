//! Process management syscalls
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;

use crate::{
    config::MAX_SYSCALL_NUM,
    loader::get_app_data_by_name,
    mm::{translated_refmut, translated_str},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskStatus,
    },
};
use crate::mm::{translated_byte_buffer, VirtAddr};
use crate::task::{check_range_all_mapped, check_range_mapped, get_task_info, insert_framed_area, remove_framed_area, TaskControlBlock};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

fn set_value(dst: Vec<&mut [u8]>, src: *const usize, len: usize) {
    let mut ptr = src;

    assert_eq!(dst.iter().map(|b| b.len()).sum::<usize>(), len);

    for buffer in dst {
        unsafe {
            buffer.copy_from_slice(
                core::slice::from_raw_parts(ptr as *const u8, buffer.len())
            );
            ptr = ptr.offset(buffer.len() as isize);
        }
    }
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let buffer = translated_byte_buffer(
        current_user_token(),
        ts as *const u8,
        mem::size_of::<TimeVal>(),
    );

    let us = get_time_us();
    let tts = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    set_value(buffer, &tts as *const TimeVal as *const usize, mem::size_of::<TimeVal>());

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let buffer = translated_byte_buffer(
        current_user_token(),
        ti as *const u8,
        mem::size_of::<TaskInfo>(),
    );

    let (ts, syscall_times, running_time) = get_task_info();

    let tti = TaskInfo {
        status: ts,
        syscall_times,
        time: running_time,
    };

    set_value(buffer, &tti as *const TaskInfo as *const usize, mem::size_of::<TaskInfo>());

    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    let end = start + len;

    let start_va: VirtAddr = start.into();
    let end_va: VirtAddr = end.into();

    if !start_va.aligned() {
        error!("sys_mmap: non-aligned start_va {:?}", start_va);
        return -1;
    }
    if port & !0x7 != 0 || port & 0x7 == 0 {
        error!("sys_mmap: invalid port {}", port);
        return -1;
    }
    if check_range_mapped(start_va, end_va) {
        error!("sys_mmap: range {:?}-{:?} mapped", start_va, end_va);
        return -1;
    }

    insert_framed_area(start, end, port);
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    let start_va: VirtAddr = start.into();

    if !start_va.aligned() {
        error!("sys_mmap: non-aligned start_va {:?}", start_va);
        return -1;
    }

    let end = start + len;
    let end_va: VirtAddr = end.into();

    if !check_range_all_mapped(start_va, end_va) {
        error!(
            "sys_mmap: part of or all range {:?}-{:?} unmapped",
            start_va, end_va
        );
        return -1;
    }

    remove_framed_area(start, end);
    0
}


/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);

    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let new_task = Arc::new(TaskControlBlock::new(data));
        let new_pid = new_task.pid.0;
        let task = current_task().unwrap();
        let mut inner = task.inner_exclusive_access();

        new_task.inner_exclusive_access().parent = Some(Arc::downgrade(&task));
        inner.children.push(new_task.clone());
        add_task(new_task);
        new_pid as isize
    } else {
        -1
    }

}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(prio: isize) -> isize {
    if prio <= 1 {
        error!(
            "kernel:pid[{}] sys_set_priority try set prio: {prio}",
            current_task().unwrap().pid.0
        );
        return -1
    }

    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    inner.priority = prio as u64;

    prio
}
