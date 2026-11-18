package nodeview

import (
	"encoding/json"
	"reflect"
	"strings"
)

type jsonShapeField struct {
	typ      reflect.Type
	optional bool
}

type jsonShapeValidator struct {
	fields map[reflect.Type]map[string]jsonShapeField
}

func validateJSONShape(d *json.Decoder, destination any) error {
	v := reflect.ValueOf(destination)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return ErrInvalid
	}
	d.UseNumber()
	validator := jsonShapeValidator{fields: make(map[reflect.Type]map[string]jsonShapeField)}
	return validator.value(d, v.Type().Elem())
}

func (v *jsonShapeValidator) value(d *json.Decoder, typ reflect.Type) error {
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	if token == nil {
		if typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			return nil
		}
		return ErrInvalid
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return ErrInvalid
		}
		fields, err := v.objectFields(typ)
		if err != nil {
			return err
		}
		seen := make(map[string]bool, len(fields))
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrInvalid
			}
			field, ok := fields[name]
			if !ok {
				return ErrInvalid
			}
			seen[name] = true
			if err := v.value(d, field.typ); err != nil {
				return err
			}
		}
		for name, field := range fields {
			if !field.optional && !seen[name] {
				return ErrInvalid
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case reflect.Array, reflect.Slice:
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			if _, ok := token.(string); !ok {
				return ErrInvalid
			}
			return nil
		}
		if token != json.Delim('[') {
			return ErrInvalid
		}
		count := 0
		for d.More() {
			if typ.Kind() == reflect.Array && count >= typ.Len() {
				return ErrInvalid
			}
			if err := v.value(d, typ.Elem()); err != nil {
				return err
			}
			count++
		}
		if typ.Kind() == reflect.Array && count != typ.Len() {
			return ErrInvalid
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	case reflect.String:
		if _, ok := token.(string); !ok {
			return ErrInvalid
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return ErrInvalid
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		if _, ok := token.(json.Number); !ok {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (v *jsonShapeValidator) objectFields(typ reflect.Type) (map[string]jsonShapeField, error) {
	if fields, ok := v.fields[typ]; ok {
		return fields, nil
	}
	fields := make(map[string]jsonShapeField, typ.NumField())
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			return nil, ErrInvalid
		}
		if name == "" {
			name = field.Name
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrInvalid
		}
		optional := false
		for _, option := range strings.Split(options, ",") {
			if option == "omitempty" || option == "omitzero" {
				optional = true
			}
		}
		fields[name] = jsonShapeField{field.Type, optional}
	}
	v.fields[typ] = fields
	return fields, nil
}
