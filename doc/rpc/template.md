# `command_name`

Brief description of what this RPC does and its primary purpose.

## Arguments

* `param1` - Description of the first parameter (type)

Please, always skip a line to render properly on man-pages.

[ # wrap with `[` and `]` to indicate an array of objects.

 {

   json_string: "str", (String, required) Description about the expected json object.

   numeric_camp: n, (numeric, optional) Describes an optional camp of the expected json object.

   boolean_camp: bool, (Boolean, Required) Describes an obligatory boolean.

 }

]

* `param2`  - Description of optional parameter (default: value) (type)

## Returns

### Ok Response
- `field1`- Description of return field (type)
- `field2` - Description of another return field (type)

### Error Enum [`CommandError`]

(Command error is a well documented enum returned client side)

## Usage Examples

```bash
<command> <param1> <param2> <optional_param>
```

## Notes
- Any important behavioral notes or requirements
- Performance considerations if applicable
- Related RPC methods or alternatives
