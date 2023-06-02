package fix

import (
	"github.com/pterm/pterm"

	"github.com/giantswarm/nancy-fixer/pkg/modules"
)

func LogParents(
	logger *pterm.Logger,
	rootParents []modules.Package,
	moduleName modules.PackageName,
) {

	switch logger.Formatter {
	case pterm.LogFormatterColorful:
		logParentsColorful(logger, rootParents, moduleName)
	case pterm.LogFormatterJSON:
		logParentsJSON(logger, rootParents, moduleName)
	}
}

func logParentsColorful(
	logger *pterm.Logger,
	rootParents []modules.Package,
	moduleName modules.PackageName,
) {
	pterm.DefaultBasicText.Println("direct dependencies that require the vulnerable package:")
	treeNodes := []pterm.TreeNode{}
	for _, parent := range rootParents {
		treeNodes = append(treeNodes, pterm.TreeNode{
			Text: string(parent.Name) + "@" + string(parent.Version),
		})
	}
	tree := pterm.TreeNode{
		Text:     string(moduleName),
		Children: treeNodes,
	}

	err := pterm.DefaultTree.WithRoot(tree).Render()
	if err != nil {
		// always returns nil
		panic(err)
	}
}

func logParentsJSON(
	logger *pterm.Logger,
	rootParents []modules.Package,
	moduleName modules.PackageName,
) {
	parentsMap := map[string]any{}
	for _, parent := range rootParents {
		parentsMap[string(parent.Name)] = parent
	}
	logger.Info("parents", pterm.DefaultLogger.ArgsFromMap(parentsMap))
}

func LogFixReasonSummary(
	logger *pterm.Logger,
	fixReasonSummary FixReasonSummary,
) {
	switch logger.Formatter {
	case pterm.LogFormatterColorful:
		logFixReasonSummaryColorful(fixReasonSummary)
	case pterm.LogFormatterJSON:
		logFixReasonSummaryJSON(logger, fixReasonSummary)
	}
}

func logFixReasonSummaryColorful(fixReasonSummary FixReasonSummary) {
	err := pterm.DefaultBarChart.WithBars([]pterm.Bar{
		{Label: "Errors", Value: fixReasonSummary.NotFixedCount},
		{Label: "Fixed via replace", Value: fixReasonSummary.FixedViaReplaceCount},
		{Label: "Fixed via parent update(s)", Value: fixReasonSummary.FixedViaParentCount},
		{Label: "Ignored", Value: fixReasonSummary.IgnoredCount},
	}).WithHorizontal().WithShowValue().Render()
	if err != nil {
		panic(err)
	}
}

func logFixReasonSummaryJSON(
	logger *pterm.Logger,
	fixReasonSummary FixReasonSummary,
) {
	logger.Info("fix reason summary", pterm.DefaultLogger.ArgsFromMap(map[string]any{
		"notFixed":        fixReasonSummary.NotFixedCount,
		"fixedViaReplace": fixReasonSummary.FixedViaReplaceCount,
		"fixedViaParent":  fixReasonSummary.FixedViaParentCount,
		"ignored":         fixReasonSummary.IgnoredCount,
	}))

}
