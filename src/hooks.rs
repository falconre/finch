use crate::error::*;
use finch::executor::Driver;
use crate::platform::Platform;

pub struct Hook<P: Platform<P>> {
    hook: Box<dyn Fn(&Driver<P>) -> Result<Option<Vec<Driver<P>>>>>,
}

impl<P: Platform<P>> Hook<P> {
    pub fn new<F: 'static>(hook: F) -> Hook<P>
    where
        F: Fn(&Driver<P>) -> Result<Option<Vec<Driver<P>>>>,
    {
        Hook {
            hook: Box::new(hook),
        }
    }

    pub fn process(&self, driver: &Driver<P>) -> Result<Option<Vec<Driver<P>>>> {
        (self.hook)(driver)
    }
}

pub struct Hooks<P: Platform<P>> {
    hooks: Vec<Hook<P>>,
}

impl<P: Platform<P>> Hooks<P> {
    pub fn new() -> Hooks<P> {
        Hooks { hooks: Vec::new() }
    }

    pub fn add_hook(&mut self, hook: Hook<P>) {
        self.hooks.push(hook);
    }

    pub fn process(&self, driver: &Driver<P>) -> Result<Option<Vec<Driver<P>>>> {
        for hook in &self.hooks {
            if let Some(drivers) = hook.process(&driver)? {
                return Ok(Some(drivers));
            }
        }
        Ok(None)
    }
}
