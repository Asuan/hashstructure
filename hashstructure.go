package hashstructure

import (
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"reflect"
	"time"
	"unsafe"
)

// HashOptions are options that are available for hashing.
type HashOptions struct {
	// Hasher is the hash function to use. If this isn't set, it will
	// default to FNV-a.
	Hasher hash.Hash64

	// TagName is the struct tag to look at when hashing the structure.
	// By default this is "hash".
	TagName string

	// ZeroNil is flag determining if nil pointer should be treated equal
	// to a zero value of pointed type. By default this is false.
	ZeroNil bool

	// IgnoreZeroValue is determining if zero value fields should be
	// ignored for hash calculation.
	IgnoreZeroValue bool

	// SlicesAsSets assumes that a `set` tag is always present for slices.
	// Default is false (in which case the tag is used instead)
	SlicesAsSets bool

	// UseStringer will attempt to use fmt.Stringer always. If the struct
	// doesn't implement fmt.Stringer, it'll fall back to trying usual tricks.
	// If this is true, and the "string" tag is also set, the tag takes
	// precedence (meaning that if the type doesn't implement fmt.Stringer, we
	// panic)
	UseStringer bool
}

// Hash returns the hash value of an arbitrary value.
//
// If opts is nil, then default options will be used. See HashOptions
// for the default values. The same *HashOptions value cannot be used
// concurrently. None of the values within a *HashOptions struct are
// safe to read/write while hashing is being done.
//
// Notes on the value:
//
//   - Unexported fields on structs are ignored and do not affect the
//     hash value.
//
//   - Adding an exported field to a struct with the zero value will change
//     the hash value.
//
// For structs, the hashing can be controlled using tags. For example:
//
//	struct {
//	    Name string
//	    UUID string `hash:"ignore"`
//	}
//
// The available tag values are:
//
//   - "ignore" or "-" - The field will be ignored and not affect the hash code.
//
//   - "set" - The field will be treated as a set, where ordering doesn't
//     affect the hash code. This only works for slices.
//
//   - "string" - The field will be hashed as a string, only works when the
//     field implements fmt.Stringer
func Hash(v any, opts *HashOptions) (uint64, error) {
	// Create default options
	if opts == nil {
		opts = &HashOptions{}
	}
	if opts.Hasher == nil {
		opts.Hasher = fnv.New64()
	}
	if opts.TagName == "" {
		opts.TagName = "hash"
	}

	// Reset the hash
	opts.Hasher.Reset()

	// Create our walker and walk the structure
	w := &walker{
		h:               opts.Hasher,
		tag:             opts.TagName,
		zeronil:         opts.ZeroNil,
		ignorezerovalue: opts.IgnoreZeroValue,
		sets:            opts.SlicesAsSets,
		stringer:        opts.UseStringer,
	}
	return w.visit(reflect.ValueOf(v), emptyOpt)
}

type walker struct {
	h               hash.Hash64
	tag             string
	zeronil         bool
	ignorezerovalue bool
	sets            bool
	stringer        bool
}

var emptyOpt = visitOpts{}

type visitOpts struct {
	// Flags are a bitmask of flags to affect behavior of this visit
	Flags visitFlag

	// Information about the struct containing this field
	Struct      any
	StructField string
}

var timeType = reflect.TypeOf(time.Time{})
var byteSliceType = reflect.TypeOf([]byte{})

func (w *walker) visit(v reflect.Value, opts visitOpts) (uint64, error) {
	t := reflect.TypeOf(0)

	// Loop since these can be wrapped in multiple layers of pointers
	// and interfaces.
	for {
		// If we have an interface, dereference it. We have to do this up
		// here because it might be a nil in there and the check below must
		// catch that.
		if v.Kind() == reflect.Interface {
			v = v.Elem()
			continue
		}

		if v.Kind() == reflect.Ptr {
			if w.zeronil {
				t = v.Type().Elem()
			}
			v = reflect.Indirect(v)
			continue
		}

		break
	}

	// If it is nil, treat it like a zero.
	if !v.IsValid() {
		v = reflect.Zero(t)
	}

	// Binary writing can use raw ints, we have to convert to
	// a sized-int, we'll choose the largest...
  switch k:= v.Kind(); k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return w.hashValue(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return w.hashValue(v.Uint())
	case reflect.Complex64, reflect.Complex128:
		return w.hashValue(v.Complex())
	case reflect.Float32, reflect.Float64:
		return w.hashValue(v.Float())
	case reflect.Bool:
		var tmp int8
		if v.Bool() {
			tmp = 1
		}
		return w.hashValue(tmp)
	case reflect.String:
		return w.hashString(v.String()), nil
	case reflect.Map:
		return w.visitMap(v, opts)
	case reflect.Chan, reflect.Func, reflect.Pointer, reflect.UnsafePointer:
		return 0, nil
	case reflect.Struct:
		if timeType == v.Type() {
			w.h.Reset()
			b, err := v.Interface().(time.Time).MarshalBinary()
			if err != nil {
				return 0, err
			}
			err = binary.Write(w.h, binary.LittleEndian, b)
			return w.h.Sum64(), err
		}

		parent := v.Interface()
		var include Includable
		if impl, ok := parent.(Includable); ok {
			include = impl
		}

		if impl, ok := parent.(Hashable); ok {
			return impl.Hash()
		}

		// If we can address this value, check if the pointer value
		// implements our interfaces and use that if so.
		if v.CanAddr() {
			vptr := v.Addr()
			parentptr := vptr.Interface()
			if impl, ok := parentptr.(Includable); ok {
				include = impl
			}

			if impl, ok := parentptr.(Hashable); ok {
				return impl.Hash()
			}
		}

		t := v.Type()
		h := w.hashString(t.Name())

		l := v.NumField()
		for i := 0; i < l; i++ {
			innerV := v.Field(i)
			fieldType := t.Field(i)
			if fieldType.PkgPath != "" {
				// Unexported
				continue
			}

			if v.CanSet() || fieldType.Name != "_" {
				tag := fieldType.Tag.Get(w.tag)
				if tag == "ignore" || tag == "-" {
					// Ignore this field
					continue
				}

				if w.ignorezerovalue {
					if innerV.IsZero() {
						continue
					}
				}

				// if string is set, use the string value
				if tag == "string" || w.stringer {
					if impl, ok := innerV.Interface().(fmt.Stringer); ok {
						innerV = reflect.ValueOf(impl.String())
					} else if tag == "string" {
						// We only show this error if the tag explicitly
						// requests a stringer.
						return 0, &ErrNotStringer{Field: v.Type().Field(i).Name}
					}
				}

				// Check if we implement includable and check it
				if include != nil {
					incl, err := include.HashInclude(fieldType.Name, innerV)
					if err != nil {
						return 0, err
					}
					if !incl {
						continue
					}
				}

				var f visitFlag
				if tag == "set" {
					f |= visitFlagSet
				}

				kh := w.hashString(fieldType.Name)
				vh, err := w.visit(innerV, visitOpts{
					Flags:       f,
					Struct:      parent,
					StructField: fieldType.Name,
				})
				if err != nil {
					return 0, err
				}

				fieldHash := hashUpdateOrdered(w.h, kh, vh)
				h = hashUpdateUnordered(h, fieldHash)
			}

			h = hashFinishUnordered(w.h, h)
		}

		return h, nil
	case reflect.Slice, reflect.Array:
		// We have two behaviors here. If it isn't a set, then we just
		// visit all the elements. If it is a set, then we do a deterministic
		// hash code.
		var h uint64
		set := (opts.Flags & visitFlagSet) != 0
		orderedHash := !(set || w.sets)

		if orderedHash && (v.Type() == byteSliceType || v.Type().AssignableTo(byteSliceType)) {
			// optimize byte array hashing in case ordered hash build
			var err error
			h, err = w.hashValue(v.Interface())
			if err != nil {
				return 0, err
			}
		} else {
			l := v.Len()
			for i := 0; i < l; i++ {
				current, err := w.visit(v.Index(i), emptyOpt)
				if err != nil {
					return 0, err
				}

				if orderedHash {
					h = hashUpdateOrdered(w.h, h, current)
				} else {
					h = hashUpdateUnordered(h, current)
				}
			}
		}

		if set {
			// Important: read the docs for hashFinishUnordered
			h = hashFinishUnordered(w.h, h)
		}

		return h, nil

	default:
		return 0, &ErrUnsupportedKind{Kind: k.String()}
	}
}

// Build the hash for the map. We do this by XOR-ing all the key
// and value hashes. This makes it deterministic despite ordering.
func (w *walker) visitMap(v reflect.Value, opts visitOpts) (uint64, error) {
	var includeMap IncludableMap
	if opts.Struct != nil {
		if v, ok := opts.Struct.(IncludableMap); ok {
			includeMap = v
		}
	}

	var h uint64
	iter := v.MapRange()
	for iter.Next() {
		k := iter.Key()
		v := iter.Value()
		if includeMap != nil {
			incl, err := includeMap.HashIncludeMap(
				opts.StructField, k.Interface(), v.Interface())
			if err != nil {
				return 0, err
			}
			if !incl {
				continue
			}
		}

		kh, err := w.visit(k, emptyOpt)
		if err != nil {
			return 0, err
		}
		vh, err := w.visit(v, emptyOpt)
		if err != nil {
			return 0, err
		}

		fieldHash := hashUpdateOrdered(w.h, kh, vh)
		h = hashUpdateUnordered(h, fieldHash)
	}

	h = hashFinishUnordered(w.h, h)
	return h, nil
}

// hashValue used to write basic math types like uint int
func (w *walker) hashValue(a any) (uint64, error) {
	w.h.Reset()
	err := binary.Write(w.h, binary.LittleEndian, a)
	return w.h.Sum64(), err
}

// hashString used to hash string value
func (w *walker) hashString(s string) uint64 {
	w.h.Reset()
	_, err := w.h.Write(unsafe.Slice(unsafe.StringData(s), len(s)))
	if err != nil {
		// We just panic if the binary writes fail because we are writing
		// an string which should never be fail-able.
		panic(err)
	}
	return w.h.Sum64()
}

func hashUpdateOrdered(h hash.Hash64, a, b uint64) uint64 {
	// For ordered updates, use a real hash function
	h.Reset()

	// We just panic if the binary writes fail because we are writing
	// an int64 which should never be fail-able.
	e1 := binary.Write(h, binary.LittleEndian, a)
	e2 := binary.Write(h, binary.LittleEndian, b)
	if e1 != nil {
		panic(e1)
	}
	if e2 != nil {
		panic(e2)
	}

	return h.Sum64()
}

func hashUpdateUnordered(a, b uint64) uint64 {
	return a ^ b
}

// After mixing a group of unique hashes with hashUpdateUnordered, it's always
// necessary to call hashFinishUnordered. Why? Because hashUpdateUnordered
// is a simple XOR, and calling hashUpdateUnordered on hashes produced by
// hashUpdateUnordered can effectively cancel out a previous change to the hash
// result if the same hash value appears later on. For example, consider:
//
//	hashUpdateUnordered(hashUpdateUnordered("A", "B"), hashUpdateUnordered("A", "C")) =
//	H("A") ^ H("B")) ^ (H("A") ^ H("C")) =
//	(H("A") ^ H("A")) ^ (H("B") ^ H(C)) =
//	H(B) ^ H(C) =
//	hashUpdateUnordered(hashUpdateUnordered("Z", "B"), hashUpdateUnordered("Z", "C"))
//
// hashFinishUnordered "hardens" the result, so that encountering partially
// overlapping input data later on in a different context won't cancel out.
func hashFinishUnordered(h hash.Hash64, a uint64) uint64 {
	h.Reset()

	// We just panic if the writes fail
	e1 := binary.Write(h, binary.LittleEndian, a)
	if e1 != nil {
		panic(e1)
	}

	return h.Sum64()
}

// visitFlag is used as a bitmask for affecting visit behavior
type visitFlag uint

const (
	visitFlagInvalid visitFlag = iota
	visitFlagSet               = iota << 1
)
