import { i as __toESM } from "../_runtime.mjs";
import { a as require_jsx_runtime, o as require_react } from "../_libs/react+tanstack__react-query.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/useFileSelection-BQQdt2sG.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var FileSelectionContext = (0, import_react.createContext)(void 0);
function FileSelectionProvider({ children }) {
	const [selectedFileId, setSelectedFileId] = (0, import_react.useState)(null);
	const [selectedFileName, setSelectedFileName] = (0, import_react.useState)(null);
	const setFileFilter = (id, name) => {
		setSelectedFileId(id);
		setSelectedFileName(name);
	};
	const clearFileFilter = () => {
		setSelectedFileId(null);
		setSelectedFileName(null);
	};
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(FileSelectionContext.Provider, {
		value: {
			selectedFileId,
			selectedFileName,
			setFileFilter,
			clearFileFilter
		},
		children
	});
}
function useFileSelection() {
	const context = (0, import_react.useContext)(FileSelectionContext);
	if (!context) throw new Error("useFileSelection doit être utilisé à l'intérieur de FileSelectionProvider");
	return context;
}
//#endregion
export { useFileSelection as n, FileSelectionProvider as t };
