# Contributing Guidelines

## Code formatting and style

Ensure source code is formatted correctly. The source code in this repository should be formatted
per the [Google Java style guide](https://google.github.io/styleguide/javaguide.html).

The maven spotless plugin can be used to check your source for any style issues:

```
bin/m spotless:check
```

Any issues that are identified can be automatically fixed prior to committing:

```
bin/m spotless:apply
```

If using vim for editing, consider using [vim-codefmt](https://github.com/google/vim-codefmt) in
conjunction with [google-java-format](https://github.com/google/google-java-format).

```
set nocompatible
filetype off
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()
Plugin 'VundleVim/Vundle.vim'
Plugin 'google/vim-maktaba'
Plugin 'google/vim-codefmt'
Plugin 'google/vim-glaive'
call vundle#end()

filetype plugin indent on

call glaive#Install()
Glaive codefmt plugin[mappings]
Glaive codefmt google_java_executable="java -jar /my/path/to/google-java-format-1.6-all-deps.jar"

augroup autoformat_settings
  autocmd FileType java AutoFormatBuffer google-java-format
augroup END
```

## Code documentation

Source code should have appropriate comments (e.g., javadoc comments) associated with exposed
functionality.

**Note:** Do not include regenerated javadoc HTML files in submitted PRs, documentation is
regenerated periodically and should not be included with functionality/code changes.
