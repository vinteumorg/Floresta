# Just Recipes on Floresta.


In floresta we love to use [Just](https://just.systems/man/en/), its fast and a easy way to maintain scripts in the project.

To organize the recipes we take advantage of groups. 

You can see the groups by
```Bash
just # So you can see our welcome message! ;)
# or
just --groups
```

## Groups Overview
### Build

Compile or install the project in different modes - use these when you need to turn code into binaries.

---

### Userland

Recipes that help users and consumers with long commands or repetitive tasks - a good example is the `install` recipe

---

### Development

Project maintenance tasks - run these when preparing code for submission or cleaning up.

---

### Linting

Code quality checks - run these frequently to keep code clean and consistent.

---

### Run

Execute the application - use these for local testing and development.

---

### Testing
End-to-end validation suites - run these to verify everything works as expected.

---

### Utility

Helper recipes - these are made to support other commands.

---

### Debug

Inspection Recipes - run these to help inspect the project during runtime.

---

## Extending and Maintaining Recipes.

You may have noticed that we like to maintain the set of groups concise and meaningful, the recipes have clear use-cases and low or any dependencies... Just like any scripting should be in this project.

You can nest groups for a command, the `install` recipe is included in `Userland` and `Build` group, and the `lint` one is included in `Linting` and `Development`.
