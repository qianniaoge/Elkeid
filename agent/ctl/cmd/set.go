/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// setCmd represents the set command
var setCmd = &cobra.Command{
	Use:   "set",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Flags().Visit(
			func(f *pflag.Flag) {
				switch f.Name {
				case "service-type":
					if f.Value.String() != "systemd" && f.Value.String() != "stsvinit" {
						cobra.CheckErr("service-type must be systemd or sysvinit")
					}
					viper.Set("SERVICE_TYPE", f.Value)
				case "id":
					viper.Set("ID", f.Value)
				case "idc":
					viper.Set("IDC", f.Value)
				}
				cobra.CheckErr(viper.WriteConfig())
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// setCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	setCmd.Flags().String("service-type", "", "systemd or stsvinit")
	setCmd.Flags().String("id", "", "id of agent")
	setCmd.Flags().String("idc", "", "internet data center")
}
