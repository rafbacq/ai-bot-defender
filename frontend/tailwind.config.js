/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["../app/templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        navy: "#012169",
        royal: "#00539B",
        prussian: "#005587",
        shale: "#0577B1",
        copper: "#C84E00",
        persimmon: "#E89923",
        dandelion: "#FFD960",
        piedmont: "#A1B70D",
        eno: "#339898",
        magnolia: "#1D6363",
        ironweed: "#993399",
        hatteras: "#E2E6ED",
        whisper: "#F3F2F1",
        ginger: "#FCF7E5",
        dogwood: "#988675",
        shackleford: "#DAD0C6",
        iron: "#262626",
        graphite: "#666666",
        granite: "#B5B5B5",
        limestone: "#E5E5E5"
      },
      fontFamily: {
        sans: ["Source Sans 3", "system-ui", "sans-serif"]
      }
    }
  },
  plugins: []
};
