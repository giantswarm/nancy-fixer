package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/giantswarm/nancy-fixer/pkg/project"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "nancy-fixer",
	Short:   "Nancy fixer is a tool to fix nancy vulnerabilities",
	Version: project.Version(),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nancy-fixer.yaml)")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "Log level")
	rootCmd.PersistentFlags().String("log-formatter", "colorful", "Log formatter")
	rootCmd.PersistentFlags().
		String("log-file", "", "Log file - if used, log to file instead of stdout")
	rootCmd.PersistentFlags().Bool("log-show-time", true, "Log time")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
