def get_dc_type(filename):
    extension = filename.split('.')[-1]
    if extension == "mp4":
        return "Video"
    if extension == "mp3" or extension == "mpd":
        return "Audio"
    if extension == "pdf":
        return "Text"
    if extension == "gltf":
        return "PhysicalObject"
    return "Unknown"