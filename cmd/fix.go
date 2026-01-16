package cmd

import (
	"errors"
	"io"
	"os"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/giantswarm/nancy-fixer/pkg/fix"
	"github.com/giantswarm/nancy-fixer/pkg/logging"
	"github.com/giantswarm/nancy-fixer/pkg/nancy"
)

// fixCmd represents the fix command
var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Fixes nancy vulnerabilities in the current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := cmd.Flag("dir").Value.String()

		writer := os.Stdout
		logFilePath := cmd.Flag("log-file").Value.String()

		if logFilePath != "" {
			logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				return err
			}
			defer func() {
				if err := logFile.Close(); err != nil {
					pterm.Error.Println("Failed to close log file:", err)
				}
			}()
			writer = logFile
		}

		logger, err := createLoggerFromFlags(cmd, writer)
		if err != nil {
			return err
		}
		logger.Debug("Logging verbosely", logger.Args("level", logger.Level))

		err = fix.Fix(logger, dir)
		if err != nil {
			// Check if this is a nancy parsing error - if so, silence usage
			if errors.Is(err, nancy.ErrNancyParsingFailed) {
				cmd.SilenceUsage = true
			}
			return err
		}

		return nil
	},
}

func createLoggerFromFlags(cmd *cobra.Command, writer io.Writer) (*pterm.Logger, error) {
	logLevel, err := logging.LogLevelFromString(cmd.Flag("log-level").Value.String())
	if err != nil {
		return nil, err
	}
	logFormatter, err := logging.LogFormatterFromString(cmd.Flag("log-formatter").Value.String())
	if err != nil {
		return nil, err
	}

	logShowTime, err := cmd.Flags().GetBool("log-show-time")
	if err != nil {
		return nil, err
	}

	config := logging.LoggerConfig{
		Level:     logLevel,
		Formatter: logFormatter,
		ShowTime:  logShowTime,
		Writer:    writer,
	}

	return logging.MakeLogger(config), nil

}

func init() {
	rootCmd.AddCommand(fixCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// fixCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// fixCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	fixCmd.PersistentFlags().String("dir", cwd, "Directory to check for vulnerable packages")
}
