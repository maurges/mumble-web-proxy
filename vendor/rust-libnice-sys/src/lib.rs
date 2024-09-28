#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

use gio_sys::*;
use gobject_sys::*;
use glib_sys::*;
use libc::*;

type gsize = usize;
type gssize = isize;
type guint64 = u64;
type guint32 = u32;
type guint16 = u16;
type guint8 = u8;
type guint = c_uint;
type gint = c_int;
type guchar = c_uchar;
type gchar = c_char;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
