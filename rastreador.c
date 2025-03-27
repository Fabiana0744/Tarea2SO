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
void uso(const char *progname) {
    fprintf(stderr, "Uso: %s [-v|-V] Prog [opciones de Prog]\n", progname);
    exit(EXIT_FAILURE);
}

/* Procesa las opciones del rastreador (-v y -V) y actualiza las banderas correspondientes. */
void procesar_opciones(int argc, char **argv, int *verbose, int *pause_flag) {
    int opt;
    while ((opt = getopt(argc, argv, "+vV")) != -1) {
        switch (opt) {
            case 'v':
                *verbose = 1;
                break;
            case 'V':
                *verbose = 1;
                *pause_flag = 1;
                break;
            default:
                uso(argv[0]);
        }
    }
}

/* Función para cargar la información de las syscalls desde un archivo CSV.
   Retorna el número de syscalls leídas o -1 en caso de error. */
int cargar_syscalls(const char *filename, syscall_info syscalls[], int max_syscalls) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error al abrir el archivo CSV");
        return -1;
    }

    char linea[MAX_LINEA];
    int contador = 0;

    // Leer y descartar la línea de encabezado.
    if (fgets(linea, sizeof(linea), fp) == NULL) {
        fclose(fp);
        return -1;
    }

    // Leer cada línea y parsear los campos separados por coma.
    while (fgets(linea, sizeof(linea), fp) && contador < max_syscalls) {
        linea[strcspn(linea, "\n")] = 0;  // Eliminar salto de línea.

        // Tokenizar la línea usando la coma como separador.
        char *token = strtok(linea, ",");
        if (token == NULL)
            continue;
        syscalls[contador].numero = atoi(token);

        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        strncpy(syscalls[contador].nombre, token, sizeof(syscalls[contador].nombre) - 1);
        syscalls[contador].nombre[sizeof(syscalls[contador].nombre) - 1] = '\0';

        token = strtok(NULL, ",");
        if (token == NULL)
            continue;
        strncpy(syscalls[contador].descripcion, token, sizeof(syscalls[contador].descripcion) - 1);
        syscalls[contador].descripcion[sizeof(syscalls[contador].descripcion) - 1] = '\0';

        contador++;
    }
    fclose(fp);
    return contador;
}

/* Busca en el arreglo de syscalls la información correspondiente al número dado.
   Retorna un puntero a la estructura si se encuentra, o NULL en caso contrario. */
syscall_info *buscar_syscall(int num, syscall_info syscalls[], int total) {
    for (int i = 0; i < total; i++) {
        if (syscalls[i].numero == num)
            return &syscalls[i];
    }
    return NULL;
}

/* Muestra la información de la syscall detectada. */
void mostrar_info_syscall(long syscall_num, syscall_info syscalls_info[], int total) {
    syscall_info *info = buscar_syscall((int)syscall_num, syscalls_info, total);
    if (info) {
        printf("Syscall detectada: %ld (%s) - %s\n",
               syscall_num, info->nombre, info->descripcion);
    } else {
        printf("Syscall detectada: %ld (nombre y descripción desconocidos)\n", syscall_num);
    }
}

/* Crea el proceso hijo y prepara la ejecución del programa a rastrear.
   Retorna el PID del hijo o -1 en caso de error. */
pid_t ejecutar_programa(int optind, int argc, char **argv) {
    pid_t child = fork();
    if (child == 0) {
        // Proceso hijo: solicitar ser rastreado y ejecutar el programa.
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            exit(EXIT_FAILURE);
        }
        execvp(argv[optind], &argv[optind]);
        perror("execvp");
        exit(EXIT_FAILURE);
    }
    return child;
}

/* Función que realiza el rastreo del proceso hijo. */
void rastrear_programa(pid_t child, syscall_info syscalls_info[], int total_syscalls, int verbose, int pause_flag) {
    int status;
    long syscall_counts[MAX_SYSCALL] = {0};

    // Bucle de rastreo hasta que el hijo termine.
    while (1) {
        wait(&status);
        if (WIFEXITED(status))
            break;

        // Intercepta la entrada o salida de una syscall.
        long syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX, NULL);
        if (syscall < 0) {
            perror("ptrace(PTRACE_PEEKUSER)");
            break;
        }

        if (syscall < MAX_SYSCALL) {
            syscall_counts[syscall]++;
        }

        if (verbose) {
            mostrar_info_syscall(syscall, syscalls_info, total_syscalls);
            if (pause_flag) {
                //printf("Presione ENTER para continuar...");
                getchar();
            }
        }

        // Reanuda la ejecución del hijo hasta la siguiente syscall.
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_SYSCALL)");
            break;
        }
    }

    // Imprime el resumen de las syscalls utilizadas.
    printf("\nResumen de syscalls:\n");
    for (int i = 0; i < MAX_SYSCALL; i++) {
        if (syscall_counts[i] > 0) {
            syscall_info *info = buscar_syscall(i, syscalls_info, total_syscalls);
            if (info)
                printf("Syscall %d (%s): %ld veces\n", i, info->nombre, syscall_counts[i]);
            else
                printf("Syscall %d (nombre desconocido): %ld veces\n", i, syscall_counts[i]);
        }
    }
}

/* Función principal */
int main(int argc, char **argv) {
    int verbose = 0, pause_flag = 0;

    // Procesar las opciones de línea de comando.
    procesar_opciones(argc, argv, &verbose, &pause_flag);

    // Verificar que se especificó el programa a ejecutar.
    if (optind >= argc) {
        fprintf(stderr, "Error: Debe especificarse el programa a ejecutar.\n");
        uso(argv[0]);
    }

    // Cargar la información de las syscalls desde el CSV.
    syscall_info syscalls_info[MAX_SYSCALL];
    int total_syscalls = cargar_syscalls("syscalls.csv", syscalls_info, MAX_SYSCALL);
    if (total_syscalls < 0) {
        fprintf(stderr, "No se pudo cargar la información de las syscalls.\n");
        exit(EXIT_FAILURE);
    }

    // Crear el proceso hijo y ejecutar el programa a rastrear.
    pid_t child = ejecutar_programa(optind, argc, argv);
    if (child < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    // En el proceso padre, iniciar el rastreo.
    rastrear_programa(child, syscalls_info, total_syscalls, verbose, pause_flag);

    return 0;
}
