import React, { createContext, useContext, useState, ReactNode } from "react";

interface FileSelectionContextProps {
  selectedFileId: number | null;
  selectedFileName: string | null;
  setFileFilter: (id: number | null, name: string | null) => void;
  clearFileFilter: () => void;
}

const FileSelectionContext = createContext<FileSelectionContextProps | undefined>(undefined);

export function FileSelectionProvider({ children }: { children: ReactNode }) {
  const [selectedFileId, setSelectedFileId] = useState<number | null>(null);
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);

  const setFileFilter = (id: number | null, name: string | null) => {
    setSelectedFileId(id);
    setSelectedFileName(name);
  };

  const clearFileFilter = () => {
    setSelectedFileId(null);
    setSelectedFileName(null);
  };

  return (
    <FileSelectionContext.Provider value={{ selectedFileId, selectedFileName, setFileFilter, clearFileFilter }}>
      {children}
    </FileSelectionContext.Provider>
  );
}

export function useFileSelection() {
  const context = useContext(FileSelectionContext);
  if (!context) {
    throw new Error("useFileSelection doit être utilisé à l'intérieur de FileSelectionProvider");
  }
  return context;
}
