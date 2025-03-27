#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>   // Para ORIG_RAX (x86-64)
#include <errno.h>

#define MAX_SYSCALL 358
#define MAX_LINEA 512

// Estructura para almacenar la información de cada syscall.
typedef struct {
    int numero;
    char nombre[32];
    char descripcion[256];
} syscall_info;

/* Imprime el mensaje de uso y termina el programa. */
void uso(const char *nombre_programa) {
    fprintf(stderr, "Uso: %s [-v|-V] Prog [opciones de Prog]\n", nombre_programa);
    exit(EXIT_FAILURE);
}

/*
 * Procesa las opciones del rastreador (-v y -V) y actualiza las banderas correspondientes.
 * Entrada:
 *   - argc: Número de argumentos.
 *   - argv: Lista de argumentos.
 *   - modo_detallado: Puntero a la variable que indica si se activa el modo detallado.
 *   - modo_pausa: Puntero a la variable que indica si se activa el modo pausa.
 * Salida:
 *   - Modifica las variables modo_detallado y modo_pausa según las opciones recibidas.
 */
void procesar_opciones(int argc, char **argv, int *modo_detallado, int *modo_pausa) {
    int opcion;
    while ((opcion = getopt(argc, argv, "+vV")) != -1) {
        switch (opcion) {
            case 'v':
                *modo_detallado = 1;
                break;
            case 'V':
                *modo_detallado = 1;
                *modo_pausa = 1;
                break;
            default:
                uso(argv[0]);
        }
    }
}


/*
 * Carga la información de las syscalls desde un archivo CSV.
 * Entrada:
 *   - nombre_archivo: Nombre del archivo CSV que contiene las syscalls.
 *   - lista_syscalls: Arreglo donde se almacenarán las syscalls.
 *   - max_syscalls: Límite máximo de syscalls a cargar.
 * Salida:
 *   - Retorna la cantidad de syscalls cargadas o -1 en caso de error.
 */
int cargar_syscalls(const char *nombre_archivo, syscall_info lista_syscalls[], int max_syscalls) {
    FILE *archivo = fopen(nombre_archivo, "r");
    if (!archivo) {
        perror("Error al abrir el archivo CSV");
        return -1;
    }

    char linea[MAX_LINEA];
    int contador = 0;

    // Leer y descartar la línea de encabezado.
    if (fgets(linea, sizeof(linea), archivo) == NULL) {
        fclose(archivo);
        return -1;
    }

    // Leer cada línea y parsear los campos separados por coma.
    while (fgets(linea, sizeof(linea), archivo) && contador < max_syscalls) {
        linea[strcspn(linea, "\n")] = 0;  // Eliminar salto de línea.

        // Tokenizar la línea usando la coma como separador.
        char *token = strtok(linea, ",");
        if (token == NULL)
            continue;
        lista_syscalls[contador].numero = atoi(token);

        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        strncpy(lista_syscalls[contador].nombre, token, sizeof(lista_syscalls[contador].nombre) - 1);
        lista_syscalls[contador].nombre[sizeof(lista_syscalls[contador].nombre) - 1] = '\0';

        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        strncpy(lista_syscalls[contador].descripcion, token, sizeof(lista_syscalls[contador].descripcion) - 1);
        lista_syscalls[contador].descripcion[sizeof(lista_syscalls[contador].descripcion) - 1] = '\0';

        contador++;
    }
    fclose(archivo);
    return contador;
}

/* Busca en el arreglo de syscalls la información correspondiente al número dado.
   Retorna un puntero a la estructura si se encuentra, o NULL en caso contrario. */
syscall_info *buscar_syscall(int numero_syscall, syscall_info lista_syscalls[], int total) {
    for (int i = 0; i < total; i++) {
        if (lista_syscalls[i].numero == numero_syscall)
            return &lista_syscalls[i];
    }
    return NULL;
}

/* Muestra la información de la syscall detectada. */
void mostrar_info_syscall(long numero_syscall, syscall_info lista_syscalls[], int total) {
    syscall_info *info = buscar_syscall((int)numero_syscall, lista_syscalls, total);
    if (info) {
        printf("Syscall detectada: %ld (%s) - %s\n",
               numero_syscall, info->nombre, info->descripcion);
    } else {
        printf("Syscall detectada: %ld (nombre y descripción desconocidos)\n", numero_syscall);
    }
}

/* 
 * Crea el proceso hijo y prepara la ejecución del programa a rastrear.
 * Entrada:
 *   - optind: Índice en argv donde comienza el nombre del programa a rastrear.
 *   - argc: Número total de argumentos de la línea de comandos.
 *   - argv: Arreglo de argumentos de la línea de comandos.
 * Salida:
 *   - PID del proceso hijo si se crea correctamente, o -1 en caso de error.
 */
pid_t ejecutar_programa(int optind, int argc, char **argv) {
    pid_t pid_hijo = fork();
    if (pid_hijo == 0) {
        // Proceso hijo: solicitar ser rastreado y ejecutar el programa.
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            exit(EXIT_FAILURE);
        }
        execvp(argv[optind], &argv[optind]);
        perror("execvp");
        exit(EXIT_FAILURE);
    }
    return pid_hijo;
}

/* 
 * Función que realiza el rastreo del proceso hijo.
 * Entrada:
 *   - pid_hijo: PID del proceso hijo a rastrear.
 *   - lista_syscalls: Arreglo con la información de las syscalls.
 *   - total_syscalls: Número total de syscalls en la lista.
 *   - modo_detallado: Indica si se debe mostrar cada syscall detectada.
 *   - modo_pausa: Indica si se debe pausar después de cada syscall detectada.
 * Salida:
 *   - Imprime un resumen de las syscalls detectadas y su frecuencia de uso.
 */
void rastrear_programa(pid_t pid_hijo, syscall_info lista_syscalls[], int total_syscalls, int modo_detallado, int modo_pausa) {
    int estado_hijo;
    long conteo_syscalls[MAX_SYSCALL] = {0};

    // Bucle de rastreo hasta que el hijo termine.
    while (1) {
        wait(&estado_hijo);
        if (WIFEXITED(estado_hijo))
            break;

        // Intercepta la entrada o salida de una syscall.
        long syscall = ptrace(PTRACE_PEEKUSER, pid_hijo, sizeof(long) * ORIG_RAX, NULL);
        if (syscall < 0) {
            perror("ptrace(PTRACE_PEEKUSER)");
            break;
        }

        if (syscall < MAX_SYSCALL) {
            conteo_syscalls[syscall]++;
        }

        if (modo_detallado) {
            mostrar_info_syscall(syscall, lista_syscalls, total_syscalls);
            if (modo_pausa) {
                //printf("Presione ENTER para continuar...");
                getchar();
            }
        }

        // Reanuda la ejecución del hijo hasta la siguiente syscall.
        if (ptrace(PTRACE_SYSCALL, pid_hijo, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_SYSCALL)");
            break;
        }
    }

    // Imprime el resumen de las syscalls utilizadas.
    printf("\nResumen de syscalls:\n");
    for (int i = 0; i < MAX_SYSCALL; i++) {
        if (conteo_syscalls[i] > 0) {
            syscall_info *info = buscar_syscall(i, lista_syscalls, total_syscalls);
            if (info)
                printf("Syscall %d (%s): %ld veces\n", i, info->nombre, conteo_syscalls[i]);
            else
                printf("Syscall %d (nombre desconocido): %ld veces\n", i, conteo_syscalls[i]);
        }
    }
}

/* Función principal */
int main(int argc, char **argv) {
    int modo_detallado = 0, modo_pausa = 0;

    // Procesar las opciones de línea de comando.
    procesar_opciones(argc, argv, &modo_detallado, &modo_pausa);

    // Verificar que se especificó el programa a ejecutar.
    if (optind >= argc) {
        fprintf(stderr, "Error: Debe especificarse el programa a ejecutar.\n");
        uso(argv[0]);
    }

    // Cargar la información de las syscalls desde el CSV.
    syscall_info lista_syscalls[MAX_SYSCALL];
    int total_syscalls = cargar_syscalls("syscalls.csv", lista_syscalls, MAX_SYSCALL);
    if (total_syscalls < 0) {
        fprintf(stderr, "No se pudo cargar la información de las syscalls.\n");
        exit(EXIT_FAILURE);
    }

    // Crear el proceso hijo y ejecutar el programa a rastrear.
    pid_t pid_hijo = ejecutar_programa(optind, argc, argv);
    if (pid_hijo < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    // En el proceso padre, iniciar el rastreo.
    rastrear_programa(pid_hijo, lista_syscalls, total_syscalls, modo_detallado, modo_pausa);

    return 0;
}
