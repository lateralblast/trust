# Changelog

## [0.2.0]

### Fixed

- XLS column widths: `set_column` had its arguments reversed, which made every column 80 wide

## [0.1.9]

### Removed

- Always-true `if check` and `if fix` guards in STDOUT text output

## [0.1.8]

### Fixed

- Previous-line lookback wrapped around to the last line of the file when processing the first line

## [0.1.7]

### Fixed

- Character classes such as `[V,v]` also matched a comma; now `[Vv]`

## [0.1.6]

### Fixed

- `[A-z]` also matched `[ \ ] ^ _` and a backtick; now `[A-Za-z]`

## [0.1.5]

### Fixed

- Text output printed the Impact section twice

## [0.1.4]

### Fixed

- `-p` and `-r` values are matched literally instead of as regular expressions

## [0.1.3]

### Fixed

- `-f` no longer requires a `pdfs` directory to exist

## [0.1.2]

### Fixed

- PDF conversion and text loading no longer go through the shell, so paths with spaces or shell characters work
- Missing `pdftotext` or `dos2unix` now reports an error instead of failing silently
- Typo in the conversion message

## [0.1.1]

### Fixed

- Output mode defaults to text when none of `-t`, `-c` or `-x` is given, instead of producing no output

## [0.1.0]

### Fixed

- Processing several PDFs (`-a`, `-p`, `-r`) with `-o` now writes all of them to the output file instead of keeping only the last one
- CSV header is written once instead of once per PDF

## [0.0.9]

### Fixed

- `-d` now sets the PDF directory

## [0.0.8]

### Fixed

- `-x` without `-o` now reports that an output file is required instead of crashing

## [0.0.7]

### Fixed

- CSV columns now match the header order (impact was written before description)

## [0.0.6]

### Fixed

- CSV rows used `.` instead of `,` between the description and rationale fields
- CSV output to STDOUT assigned to `vendor` instead of concatenating, corrupting the row

## [0.0.5]

### Fixed

- `-o` into a directory that does not exist crashed (`File.mkpath` should be `FileUtils.mkpath`)

## [0.0.4] - 2014-08-25

### Fixed

- Input file processing

## [0.0.3] - 2014-08-24

### Added

- Initial XLS support

## [0.0.2]

### Added

- Initial CSV support

## [0.0.1]

### Added

- Initial text support
