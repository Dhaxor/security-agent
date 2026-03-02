from tools.tool_runner import ToolRunner

def main():
    runner = ToolRunner()
    runner.run_slither_file("test_solidity.sol")

if __name__ == "__main__":
    main()