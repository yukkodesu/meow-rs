use std::{
    io,
    marker::PhantomData,
    os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
    rc::Rc,
    sync::Arc,
};

use windows_sys::Win32::{
    Foundation::{ERROR_NO_TOKEN, HANDLE},
    Security::{
        CopySid, DuplicateTokenEx, EqualSid, GetLengthSid, GetTokenInformation, RevertToSelf,
        SecurityImpersonation, TokenElevation, TokenGroups, TokenImpersonation, TokenOwner,
        TokenUser, PSID, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_OWNER,
        TOKEN_QUERY, TOKEN_USER,
    },
    System::{
        SystemServices::{SE_GROUP_ENABLED, SE_GROUP_OWNER, SE_GROUP_USE_FOR_DENY_ONLY},
        Threading::{GetCurrentThread, OpenThreadToken, SetThreadToken},
    },
};

#[derive(Clone)]
pub struct WindowsCaller(Arc<Identity>);

struct Identity {
    token: OwnedHandle,
    user: Sid,
    elevated_owner: Option<Sid>,
}

struct Sid(Vec<u32>);

impl Sid {
    unsafe fn copy(source: PSID) -> io::Result<Self> {
        let length = unsafe { GetLengthSid(source) };
        let sid = Self(vec![0; (length as usize).div_ceil(4)]);
        check(unsafe { CopySid(length, sid.as_ptr(), source) })?;
        Ok(sid)
    }

    fn as_ptr(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    fn equals(&self, other: PSID) -> bool {
        unsafe { EqualSid(self.as_ptr(), other) != 0 }
    }
}

impl WindowsCaller {
    pub fn duplicate(token: BorrowedHandle<'_>) -> io::Result<Self> {
        let mut duplicated = ptr::null_mut();
        check(unsafe {
            DuplicateTokenEx(
                token.as_raw_handle(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut duplicated,
            )
        })?;
        let token = unsafe { OwnedHandle::from_raw_handle(duplicated) };
        let user_info = token_info(&token, TokenUser)?;
        let user = unsafe { Sid::copy((*user_info.as_ptr().cast::<TOKEN_USER>()).User.Sid)? };
        let owner_info = token_info(&token, TokenOwner)?;
        let owner = unsafe { (*owner_info.as_ptr().cast::<TOKEN_OWNER>()).Owner };
        let elevation_info = token_info(&token, TokenElevation)?;
        let elevated =
            unsafe { (*elevation_info.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0 };
        let elevated_owner = if elevated && !user.equals(owner) {
            let groups_info = token_info(&token, TokenGroups)?;
            let groups = unsafe { &*groups_info.as_ptr().cast::<TOKEN_GROUPS>() };
            let groups = unsafe {
                std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
            };
            let accepted = groups.iter().any(|group| {
                let required = (SE_GROUP_ENABLED | SE_GROUP_OWNER) as u32;
                group.Attributes & required == required
                    && group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
                    && unsafe { EqualSid(group.Sid, owner) != 0 }
            });
            if accepted {
                Some(unsafe { Sid::copy(owner)? })
            } else {
                None
            }
        } else {
            None
        };
        Ok(Self(Arc::new(Identity {
            token,
            user,
            elevated_owner,
        })))
    }

    pub(super) fn same_token(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(super) fn user(&self) -> PSID {
        self.0.user.as_ptr()
    }

    pub(super) fn accepts_owner(&self, owner: PSID) -> bool {
        self.0.user.equals(owner)
            || self
                .0
                .elevated_owner
                .as_ref()
                .is_some_and(|sid| sid.equals(owner))
    }

    pub(super) fn enter(&self) -> io::Result<Impersonation> {
        let mut previous = ptr::null_mut();
        let previous = if unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                1,
                &mut previous,
            )
        } != 0
        {
            Some(unsafe { OwnedHandle::from_raw_handle(previous) })
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                return Err(error);
            }
            None
        };
        check(unsafe { SetThreadToken(ptr::null(), self.0.token.as_raw_handle()) })?;
        Ok(Impersonation {
            previous,
            _thread: PhantomData,
        })
    }
}

pub(super) struct Impersonation {
    previous: Option<OwnedHandle>,
    _thread: PhantomData<Rc<()>>,
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        let restored = unsafe {
            match &self.previous {
                Some(token) => SetThreadToken(ptr::null(), token.as_raw_handle()),
                None => RevertToSelf(),
            }
        };
        // A pooled thread must never survive with another caller's credentials.
        if restored == 0 {
            std::process::abort();
        }
    }
}

fn token_info(token: &OwnedHandle, class: i32) -> io::Result<Vec<usize>> {
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    check(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    })?;
    Ok(buffer)
}

pub(super) fn check(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn raw(handle: &impl AsRawHandle) -> HANDLE {
    handle.as_raw_handle()
}
