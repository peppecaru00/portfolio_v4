export interface Project {
  id: string;
  title: string;
  category: string;
  year: string;
  image: string;
  videoUrl?: string;
  aspectRatio?: string;
  description?: string;
  metaData?: Record<string, any>;
}

const metaFiles = import.meta.glob("/public/projects/*/meta.json", {
  eager: true,
  import: "default",
});
const coverFiles = import.meta.glob("/public/projects/*/cover.*", {
  eager: true,
  as: "url",
});
const videoFiles = import.meta.glob("/public/projects/*/*.mp4", {
  eager: true,
  as: "url",
});

export const projects: Project[] = Object.entries(metaFiles).map(
  ([path, meta]: [string, any]) => {
    const parts = path.split("/");
    const id = parts[parts.length - 2];

    // Extract specific properties and keep the rest in metaData
    const {
      title,
      category,
      year,
      videoUrl,
      aspectRatio,
      description,
      ...rest
    } = meta;

    const projectCoverPrefix = `/public/projects/${id}/cover.`;
    const covers = Object.keys(coverFiles).filter((f) =>
      f.startsWith(projectCoverPrefix),
    );

    let resolvedImage = "";
    let resolvedVideo = videoUrl;

    for (const file of covers) {
      if (file.endsWith(".mp4") || file.endsWith(".webm")) {
        resolvedVideo = resolvedVideo || file.replace("/public", "");
      } else {
        resolvedImage = file.replace("/public", "");
      }
    }

    const projectVideoPrefix = `/public/projects/${id}/`;
    const videos = Object.keys(videoFiles).filter((f) =>
      f.startsWith(projectVideoPrefix),
    );
    for (const file of videos) {
      if (!file.includes("/cover.mp4")) {
        resolvedVideo = resolvedVideo || file.replace("/public", "");
      }
    }

    return {
      id,
      title: title || id,
      category: category || "",
      year: year || "",
      image: resolvedImage,
      videoUrl: resolvedVideo,
      aspectRatio: aspectRatio,
      description: description,
      metaData: rest,
    };
  },
);
