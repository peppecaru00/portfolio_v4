import { projects } from "~/data/projects";
import type { Project } from "~/data/projects";

export const useProjects = () => {
  const getProjectById = (id: string): Project | undefined => {
    return projects.find((p) => p.id === id);
  };

  return {
    projects,
    getProjectById,
  };
};
