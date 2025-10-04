# Just Recipes on Floresta.

In floresta we use [Just](https://just.systems/man/en/), as a fast and easy way to maintain scripts in the project.

To organize the recipes we take advantage of groups.

You can see the groups with:

```Bash
just # So you can see our welcome message! ;)
# or
just --groups
```

## Groups Overview

### Aliases

Recipes that help users and consumers with long commands or repetitive tasks - a good example is the `install` recipe.

---

### Development

Project maintenance tasks - run these when preparing code for submission or cleaning up data directories.

#### Linting

Code quality checks - run these frequently to keep code clean and consistent. We recommend using `just lint` which runs most of our CI lint checks and formats the code. For a complete lint check use `just lint-features`. If you only want formatting, use `just fmt`.

#### Testing

End-to-end testing suites - run these to verify everything works as expected.

---

### Running

Build and Execute the application - use these for local testing and development.

---

### Utility

Helper recipes - these are made to support other commands.

---

## Extending and Maintaining Recipes.

You may have noticed that we like to maintain the set of groups concise and meaningful, the recipes have clear use-cases and none or low dependencies... Just like any scripting should be in this project.

You can nest groups for a command, the `install` recipe is included in `Aliases` and `Running` group, and the `lint` one is included in `Linting` and `Development`.
