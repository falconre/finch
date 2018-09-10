# Finch

Finch is a Symbolic Executor over [Falcon](https://github.com/falconre/falcon) IL. If it lifts to Falcon IL, it symbolically executes with Finch.

For an introduction to Finch, see [this blog post](http://reversing.io/posts/introducing-finch/).

# Building

Finch requires the same dependencies as Falcon and [falcon-z3](https://github.com/falconre/falcon-z3). There is a Dockerfile in the dockers/ directory, which will create an appropriate environment for Finch. If you don't want to use Docker, it is still recommended you use the Dockerfile as a reference for how to install dependencies.
