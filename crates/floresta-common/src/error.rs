/// A no-std implementation of the `Error` trait for floresta
use crate::prelude::fmt::Debug;
use crate::prelude::Display;

/// `Error` is a trait representing the basic expectations for error values,
/// i.e., values of type `E` in [`Result<T, E>`]. Errors must describe
/// themselves through the [`Display`] and [`Debug`] traits. This is a simplified implementation of
/// the trait, used inside floresta, in case of a no-std environment.
pub trait Error: Debug + Display {}
