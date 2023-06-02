package cmd

import (
	"io"
	"os"

	"github.com/giantswarm/microerror"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/giantswarm/nancy-fixer/pkg/fix"
	"github.com/giantswarm/nancy-fixer/pkg/logging"
)

// fixCmd represents the fix command
var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := cmd.Flag("dir").Value.String()

		writer := os.Stdout
		logFilePath := cmd.Flag("log-file").Value.String()

		if logFilePath != "" {
			logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return microerror.Mask(err)
			}
			defer logFile.Close()
			writer = logFile
		}

		logger, err := createLoggerFromFlags(cmd, writer)

		err = fix.Fix(logger, dir)
		if err != nil {
			return microerror.Mask(err)
		}

		return nil
	},
}

func createLoggerFromFlags(cmd *cobra.Command, writer io.Writer) (*pterm.Logger, error) {
	logLevel, err := logging.LogLevelFromString(cmd.Flag("log-level").Value.String())
	if err != nil {
		return nil, microerror.Mask(err)
	}

	logFormatter, err := logging.LogFormatterFromString(cmd.Flag("log-formatter").Value.String())
	if err != nil {
		return nil, microerror.Mask(err)
	}

	logShowTime, err := cmd.Flags().GetBool("log-show-time")

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
