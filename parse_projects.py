import os
import json

projects = []
projects_dir = 'public/projects'

if os.path.exists(projects_dir):
    dirs = [d for d in os.listdir(projects_dir) if os.path.isdir(os.path.join(projects_dir, d))]
    dirs.sort()
    
    for d in dirs:
        meta_path = os.path.join(projects_dir, d, 'meta.json')
        cover_path = f'/projects/{d}/cover.webp'
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
            except Exception as e:
                meta = {}
            
            p = {
                'id': d,
                'title': meta.get('title', d),
                'category': meta.get('category', ''),
                'year': meta.get('year', ''),
                'image': cover_path,
            }
            if meta.get('videoUrl'):
                p['videoUrl'] = meta['videoUrl']
            projects.append(p)

with open('data/projects.ts', 'w', encoding='utf-8') as f:
    f.write('export interface Project {\n  id: string;\n  title: string;\n  category: string;\n  year: string;\n  image: string;\n  videoUrl?: string;\n  aspectRatio?: string;\n}\n\n')
    f.write('export const projects: Project[] = ')
    f.write(json.dumps(projects, indent=2))
    f.write(';\n')
