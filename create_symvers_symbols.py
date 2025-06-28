import sys
import re

def parse_modpost_errors(modpost_errors):
    # This regex will match the "undefined" errors and extract the symbol name and the module name
    error_pattern = re.compile(r'ERROR: modpost: "(?P<symbol>.*?)" \[(?P<module>.*?)\] undefined!')

    symbols = set()

    # Parse each error and extract the symbol
    for line in modpost_errors.splitlines():
        match = error_pattern.match(line)
        if match:
            symbol = match.group("symbol")
            symbols.add(symbol)

    return symbols

def generate_symvers(symbols, module_name):
    # Create the .symvers format for the given symbols
    symvers_lines = []

    for symbol in symbols:
        # In the requested format: address symbol_name module_name EXPORT_SYMBOL
        # For simplicity, we'll assume the address is 0x00000000
        symvers_lines.append(f"0x00000000\t{symbol}\t{module_name}\tEXPORT_SYMBOL\t")

    return "\n".join(symvers_lines)

def main():
    # Read modpost errors from stdin
    modpost_errors = sys.stdin.read()

    # Extract the symbols from the modpost errors
    symbols = parse_modpost_errors(modpost_errors)

    # Module name can be extracted from the error lines, or you can hardcode it if known
    module_name = "module"  # Adjust this as needed

    # Generate the .symvers content
    symvers_content = generate_symvers(symbols, module_name)

    # Output the result to stdout
    sys.stdout.write(symvers_content + "\n")

if __name__ == "__main__":
    main()
