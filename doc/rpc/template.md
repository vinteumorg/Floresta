# `command_name`

Brief description of what this RPC does and its primary purpose.

## Usage

### Command Signature

floresta-cli <command> <param1, parameter_type> <param2> <optional_flag, (--f or --flag)> 

### Examples

```bash
floresta-cli templatecommand -f "data"
floresta-cli templatecommand --flag "moredata"
floresta-cli templatecommand  123
```

## Arguments

* `param1` - (type, required or optional) Description of the first parameter

Please, always skip a line to render properly on man-pages.

```json5
// Wrap with `[` and `]` to indicate an array of objects
[

  {

    "json_string": "str", // (String, required) Description about the expected JSON object.

    "numeric_field": 123, // (Numeric, optional) Describes an optional field.

    "boolean_field": true // (Boolean, required) Describes an obligatory boolean.

  }

]
```

* `param2`  - Description of optional parameter (default: value) (type)

## Returns

### Ok Response

- `field1`- (type) Description of return field
- `field2` - (type) Description of another return field

### Error Enum `CommandError`

(Command error is a well documented enum returned client side)

## Notes

- Any important behavioral notes or requirements
- Performance considerations if applicable
- Related RPC methods or alternatives
