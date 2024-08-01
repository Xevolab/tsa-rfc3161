/*
 * Author    : Francesco
 * Created at: 2024-02-03 11:29
 * Edited by : Francesco
 * Edited at : 2024-07-31 19:25
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

module.exports = {
	"root": true,
	"extends": [
		"@xevolab/eslint-config/backend",
		"plugin:@typescript-eslint/eslint-recommended",
		"plugin:@typescript-eslint/recommended"
	],
	"parser": "@typescript-eslint/parser",
	"plugins": [
		"@typescript-eslint"
	],
	"settings": {
		"import/resolver": {
			"node": {
				"extensions": [".js", ".jsx", ".ts", ".tsx"]
			}
		}
	},
	rules: {
		"import/extensions": 0
	}
}
