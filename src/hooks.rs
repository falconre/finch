use crate::error::*;
use finch::executor::Driver;

pub struct Hook {
    hook: Box<dyn Fn(&Driver) -> Result<Option<Vec<Driver>>>>,
}

impl Hook {
    pub fn new<F: 'static>(hook: F) -> Hook
    where
        F: Fn(&Driver) -> Result<Option<Vec<Driver>>>,
    {
        Hook {
            hook: Box::new(hook),
        }
    }

    pub fn process(&self, driver: &Driver) -> Result<Option<Vec<Driver>>> {
        (self.hook)(driver)
    }
}

pub struct Hooks {
    hooks: Vec<Hook>,
}

impl Hooks {
    pub fn new() -> Hooks {
        Hooks { hooks: Vec::new() }
    }

    pub fn add_hook(&mut self, hook: Hook) {
        self.hooks.push(hook);
    }

    pub fn process(&self, driver: &Driver) -> Result<Option<Vec<Driver>>> {
        for hook in &self.hooks {
            if let Some(drivers) = hook.process(driver)? {
                return Ok(Some(drivers));
            }
        }
        Ok(None)
    }
}

impl Default for Hooks {
    fn default() -> Hooks {
        Hooks::new()
    }
}
