# Code Style Guidelines

This document describes the styles and patterns used this project. All fresh code should conform to these rules, so it is as easy to maintain as existing code.

## Indentation

- Use spaces, not tabs. Tabs should only appear in files that require them for semantic meaning, like Makefiles.

- The indent size is 4 spaces.

- The contents of an outermost **namespace block** (and any nested namespaces with the same scope) should not be indented. The contents of other nested namespaces should be indented.

**Right:**
```
namespace MyNamespace {

class MyClass {
    MyClass();
    ...
};

}
```
**Wrong:**
```
namespace MyNamespace {

class MyClass {
    MyClass();
    ...
};

}
```

- A case label should line up with its switch statement. The case statement is indented.

**Right:**
```
switch (condition) {
case foo:
case bar:
    i++;
    break;
default:
    i--;
}
```
**Wrong:**
```
switch (condition) {
    case foo:
    case bar:
        i++;
        break;
    default:
        i--;
}
```

## Line breaking

- Statements longer than 100 columns should be broken into sensible chunks

- Each statement should get its own line.

**Right:**
```
x++;
y++;
if (condition) {
    do();
    }
```
**Wrong:**
```
x++; y++;
if (condition) { do(); }
```

## Braces

- Function definitions: place each brace on its own line.

**Right:**
```
int Function()
{
    ...
}
```
**Wrong:**
```
int Function() {
    ...
}
```

- Inline functions defined inside class: place the open brace on the line preceding the code block.

**Right:**
```
class MyClass {
    inline int Function1() {
        ...
    }
    inline int Function2() { ... }
    ...
};
```
**Wrong:**
```
class MyClass {
    inline int Function1()
    {
        ...
    }
    ...
};
```

- Other braces: place the open brace on the line preceding the code block; place the close brace on its own line.

**Right:**
```
class MyClass {
    ...
};

namespace MyNamespace {
    ...
}

for (int i = 0; i < 10; ++i) {
    ...
}
```
**Wrong:**
```
class MyClass
{
    ...
};

namespace MyNamespace
{
    ...
}

for (int i = 0; i < 10; ++i)
{
    ...
}
```

- Always brace controlled statements, even a single-line consequent of `if else else`. This is redundant, typically, but it avoids dangling else bugs, so it’s safer at scale than fine-tuning.

**Right:**
```
if (condition) {
    do();
    }
```
**Wrong:**
```
if (condition) do();
```

## Spaces

- No blank spaces at the end of a line

- Do not place spaces around unary operators.


**Right:**
```
i++;
```
**Wrong:**
```
i ++;
```

- Use one space around (on each side of) most binary and ternary operators,
such as any of these:

`	=  +  -  <  >  *  /  %  |  &  ^  <=  >=  ==  !=  ?  :`

but no space after unary operators:

`	&  *  +  -  ~  !  sizeof  typeof  alignof  defined `

and no space around the `.` and `->` structure member operators.


**Right:**
```
y = m * x + b;
f(a, b);
c = a | b;
return condition ? 1 : 0;
```
**Wrong:**
```
y=m*x+b;
f(a,b);
c = a|b;
return condition ? 1:0;
```

- Do not place spaces before comma and semicolon.

**Right:**
```
for (int i = 0; i < 10; ++i)
    doSomething();

f(a, b);
```
**Wrong:**
```
for (int i = 0 ; i < 10 ; ++i)
    doSomething();

f(a , b) ;
```

- Place spaces between control statements and their parentheses.

**Right:**
```
if (condition)
    doIt();
```
**Wrong:**
```
if(condition)
    doIt();
```

- Do not place spaces between a function and its parentheses, or between a parenthesis and its content.

**Right:**
```
f(a, b);
```
**Wrong:**
```
f (a, b);
f( a, b );
```

- When initializing an object, place a space before the leading brace as well as between the braces and their content.

**Right:**
```
Foo foo { bar };
```
**Wrong:**
```
Foo foo{ bar };
Foo foo {bar};
```

## Names

- Data members in C++ classes should be private. Static data members should be prefixed by `"s_"`. Other data members should be prefixed by `"m_"`. Global variables should start with `"g_"`

**Right:**
```
int g_variable;
class String {
public:
    ...

private:
    short m_length;
};
```
**Wrong:**
```
int variable;
class String {
public:
    ...

private:
    short length;
};
```

- Precede boolean values with words like `"is"`.

**Right:**
```
bool isValid;
```
**Wrong:**
```
bool Valid;
```

- Precede setters with the word `"set"`. Precede getters with the word `"get"`.

**Right:**
```
void setCount(size_t); // sets m_count
size_t getCount(); // returns m_count
```
**Wrong:**
```
void Count(size_t); // sets m_count
size_t Count(); // returns m_count
```

## Pointers and References

- Put * and & by the variable name rather than the type.

**Right:**
```
bool fooBar(bool Baz, char *str, std::vector<int> &Result);
```
**Wrong:**
```
bool fooBar(bool Baz, char *str, std::vector<int> &Result);
```

## #include Statements

- Include headers in the following order: `config.h`, Related header, C system headers, C++ standard library headers, other libraries' headers, your project's headers..
    
    * **Pros:**
    - Forward declarations can save compile time, as #includes force the compiler to open more files and process more input.
    - Forward declarations can save on unnecessary recompilation. #includes can force your code to be recompiled more often, due to unrelated changes in the header.
    * **Cons:**
    - Forward declarations can hide a dependency, allowing user code to skip necessary recompilation when headers change.
    - A forward declaration as opposed to an #include statement makes it difficult for automatic tooling to discover the module defining the symbol.
    - A forward declaration may be broken by subsequent changes to the library. Forward declarations of functions and templates can prevent the header owners from making otherwise-compatible changes to their APIs, such as widening a parameter type, adding a template parameter with a default value, or migrating to a new namespace.
    - Forward declaring multiple symbols from a header can be more verbose than simply #includeing the header.

**Right:**
```
#include "config.h"

#include "foo/server/fooserver.h"

#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/commandlineflags.h"
#include "foo/server/bar.h"
```

## Comments

- Comments are important for readability and maintainability. When writing comments, write them as English prose, using proper capitalization, punctuation, etc.
- Generally, you want your comments to tell **WHAT** your code does, not **HOW**
- In general, prefer C++-style comments for one line.
- The preferred style for long (multi-line) comments is:
```
	/* The preferred comment style for (multi-line) comments
	 * looks like this.
	 */
```
